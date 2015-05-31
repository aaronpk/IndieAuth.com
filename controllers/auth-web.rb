class Controller < Sinatra::Base


  def verify_me_param
    me = params[:me]

    if me.nil? || me == ""
      json_error 200, {error: 'invalid_input', error_description: 'parameter "me" is required'}
    end

    # Prepend "http" unless it's already there
    me = "http://#{me}" unless me.start_with?('http')
    me
  end

  def verify_profile_param
    profile = params[:profile]

    if profile.nil? || profile == ""
      json_error 200, {error: 'invalid_input', error_description: 'parameter "profile" is required'}
    end

    profile
  end

  def find_all_supported_providers(me_parser, profile=nil)
    # Find all the rel=me links on the specified page
    begin
      links = me_parser.rel_me_links
    rescue SocketError
      json_error 200, {error: 'connection_error', error_description: "Error retrieving: #{me_parser.url}"}
    end

    if links.nil?
      json_error 200, {error: 'no_links_found', error_description: "No links found on #{me_parser.url} or could not parse the page"}
    end

    links
  end

  def find_auth_endpoints(me_parser) 
    begin
      endpoints = me_parser.auth_endpoints
    rescue SocketError
      json_error 200, {error: 'connection_error', error_description: "Error retrieving: #{me_parser.url}"}
    end

    endpoints
  end

  def get_gpg_keys(me_parser)
    begin
      keys = me_parser.gpg_keys
    rescue SocketError
      json_error 200, {error: 'connection_error', error_description: "Error retrieving keys at #{me_parser.url}"}
    end

    keys
  end

  def verify_user_profile(me_parser, profile, me)

    # First check if there's already a matching profile record for this user 
    existing = Profile.find :me => me, :profile => profile
    puts "Checking for existing profile: #{me}, #{profile}"

    if !existing
      # Checks the URL against the list of regexes to see what provider it is
      # Does not fetch the page contents
      profile_parser = RelParser.new profile
      provider = Provider.provider_for_url profile

      if provider.nil?
        json_error 200, {error: 'unsupported_provider', error_description: 'The specified link is not a supported provider'}
      end

      puts "No existing provider, but parsed as: #{provider}"
    else
      profile_parser = RelParser.new profile
      provider = existing['provider']
      puts "Found existing: #{provider}"
    end

    if provider == 'sms' or provider == 'email'
      verified = true
      error_description = nil
    elsif provider == 'gpg'
      verified = true
      error_description = nil
    elsif provider == 'indieauth'
      # Make an HTTP request to the auth server and check that it responds with an "IndieAuth: authorization_endpoint" header
      # But return verified=false if it's actually this server
      if "#{SiteConfig.root}/auth" == profile
        verified = false
        error_description = 'This auth server cannot be used to authenticate to itself'
      else
        verified, error_description = me_parser.verify_auth_endpoint profile, profile_parser
      end
    else
      # This does an HTTP request
      verified, error_description = me_parser.verify_link profile, profile_parser
    end

    # Cache this in Redis, or remove if it's not verified
    if verified
      Profile.save({:me => me, :profile => profile}, {:provider => provider, :created_at => Time.now.to_i})
    else
      Profile.delete :me => me, :profile => profile
    end

    return provider, verified, error_description
  end

  def auth_param_setup
    # Double check they provided valid parameters for "me" and "profile"

    me = verify_me_param
    profile = verify_profile_param

    me_parser = RelParser.new me

    # Don't actually look for *all* links. Just look for the specific one we're looking for in #{profile} and stop there
    if !me_parser.links_to profile
      json_error 200, {error: 'invalid_input', error_description: "\"#{params[:profile]}\" was not found on the site \"#{params[:me]}\""}
    end

    provider, verified, error_description = verify_user_profile me_parser, profile, me
    return me, profile, provider, verified, error_description
  end

  def save_response_type
    # If a client_id is specified, assume this is a new client and use "code" for the name instead
    session[:response_type] = 'token'
    if params[:client_id]
      session[:response_type] = 'code'
    end
  end

  # 1. Begin the auth process
  get '/auth' do
    title "IndieAuth - Sign in with your domain name"
    @me = params[:me]

    if @me.nil?
      title "About IndieAuth"
      halt 200, {
        'IndieAuth' => 'authorization_endpoint'  # tell clients this is an indieauth endpoint
      }, erb(:auth_about)
    end

    if !@me.match(/^http/)
      @me = "http://#{@me}"
    end
    
    @profiles = []
    # Look up their cached profiles
    profiles = Profile.all :me => @me
    profiles.each do |profile, data|
      data = JSON.parse data
      @profiles << {
        'href' => profile,
        'provider' => data['provider']
      }
    end

    save_response_type
    session[:state] = params[:state]
    session[:scope] = params[:scope]

    @redirect_uri = params[:redirect_uri]
    @client_id = params[:client_id]
    @state = params[:state]
    @scope = params[:scope]

    @app_name = 'Unknown App'
    @app_logo = nil

    if params[:client_id]
      # Remove visible http and trailing slash from the display name
      @app_name = params[:client_id].gsub(/https?:\/\//, '').gsub(/\/$/, '')
      # Look for an h-card on the URL indicated by the client_id
      begin
        client_id = URI.parse params[:client_id]
        if ['https','http'].include? client_id.scheme and !client_id.host.nil?
          client_id.path = '/' if client_id.path == ''
          client = Microformats2.parse client_id
          if client.x_app.name
            @app_name = client.x_app.name
          end
          if client.x_app.logo
            @app_logo = client_id + URI.parse(client.x_app.logo.to_s)
          end
        end
      rescue
      end

    elsif params[:redirect_uri]
      @app_name = params[:redirect_uri].gsub(/https?:\/\//, '')
    end

    # Pre-generate the GPG challenge if there is already a GPG profile for this user
    @gpg_challenges = []
    profiles = Profile.all(:me => @me)
    profiles.each do |profile, data|
      data = JSON.parse data
      if data['provider'] == 'gpg'
        @gpg_challenges << {
          :profile => profile,
          :challenge => generate_gpg_challenge(@me, profile, params)
        }
      end
    end

    halt 200, {
      'IndieAuth' => 'authorization_endpoint'
    }, erb(:auth)
  end

  # 2. Return all supported providers on the given page
  # Params: 
  #  * me=example.com
  get '/auth/supported_providers.json' do
    me = verify_me_param

    me_parser = RelParser.new me

    # Check for supported auth providers
    begin
      links = find_all_supported_providers me_parser
    rescue RelParser::InsecureRedirectError => e
      json_error 200, {error: 'insecure_redirect', error_description: e.message}
    rescue RelParser::SSLError => e
      json_error 200, {error: 'ssl_error', error_description: "There was an SSL error connecting to #{e.url}"}
    rescue RelParser::InvalidContentError => e
      json_error 200, {error: 'content_type_error', error_description: e.message}
    rescue Exception => e
      json_error 200, {error: 'unknown', error_description: "Unknown error retrieving #{me_parser.url}: #{e.message}"}
    end

    # Check if the website points to its own IndieAuth server
    auth_endpoints = []
    begin
      auth_endpoints = find_auth_endpoints me_parser
    rescue Exception => e
      json_error 200, {error: 'unknown', error_description: "Unknown error retrieving #{me_parser.url}: #{e.message}"}
    end

    gpg_keys = []
    begin
      gpg_keys = get_gpg_keys me_parser
    rescue Exception => e
      json_error 200, {error: 'unknown', error_description: "Unknown error retrieving GPG keys for #{me_parser.url}: #{e.message}"}
    end

    User.set_last_refresh me, Time.now.to_i

    # Delete all old profiles that aren't linked on the user's page anymore
    Profile.all(:me => me).each do |profile,data|
      data = JSON.parse data
      if !['server'].include? data['provider'] and !links.include? profile
        puts "Link to #{profile} no longer found, deactivating"
        Profile.delete :me => me, :profile => profile
      end
      # TODO: Also deactivate old auth servers
    end

    # Check each link to see if it's a supported provider
    links_response = []

    links.each do |link|
      verified = nil

      # Checks the URL against the list of regexes to see what provider it is
      # Does not fetch the page contents
      profile_parser = RelParser.new link
      provider = Provider.provider_for_url link

      if provider && (provider == 'sms' or provider == 'email')
        verified = true
        # Run verify_user_profile which will save the profile in the DB. Since it's only
        # running for SMS and Email profiles, it won't trigger an HTTP request.
        verify_user_profile me_parser, link, me
      end

      links_response << {
        profile: link,
        provider: (provider ? provider : nil),
        verified: verified
      }
    end

    if auth_endpoints.length > 0
      provider = 'indieauth'

      auth_endpoints.each do |endpoint|
        # Store it now because when we verify it with the verify_link.json request, it doesn't know what provider it is and this will tell it
        Profile.save({:me => me, :profile => endpoint}, {:provider => 'indieauth', :created_at => Time.now.to_i})
        links_response << {
          profile: endpoint,
          provider: 'indieauth',
          verified: nil
        }
      end
    end

    if gpg_keys.length > 0
      provider = 'gpg'

      gpg_keys.each do |key|
        links_response << {
          profile: key['href'],
          provider: 'gpg',
          verified: true
        }
      end
    end

    json_response 200, {links: links_response}
  end

  # 3. Verify a link has a rel=me relation back to the specified site
  # Params:
  #  * me=example.com
  #  * profile=provider.com/user/xxxxx
  get '/auth/verify_link.json' do

    begin
      me, profile, provider, verified, error_description = auth_param_setup
    rescue RelParser::InsecureRedirectError => e
      json_error 200, {error: 'insecure_redirect', error_description: e.message}
    rescue RelParser::SSLError => e
      json_error 200, {error: 'ssl_error', error_description: "There was an SSL error connecting to #{e.url}"}
    rescue Exception => e
      json_error 200, {error: 'unknown', error_description: "Unknown error: #{e.message}"}
    end

    response = {
      me: me, 
      profile: profile, 
      provider: provider, 
      verified: verified,
      error: true,
      error_description: error_description,
      auth_path: (verified ? Provider.auth_path(provider, profile, me) : false)
    }

    if error_description
      response[:error] = 'self'
    end

    json_response 200, response
  end

  get '/auth/start' do

    # TODO: handle these errors differently by redirecting to an error page instead of returning JSON
    me = verify_me_param
    profile = verify_profile_param

    me_parser = RelParser.new me

    begin
      links = find_all_supported_providers me_parser
      auth_endpoints = find_auth_endpoints me_parser
      gpg_keys = get_gpg_keys me_parser
    rescue Exception => e
      @message = "Unknown error retrieving #{me_parser.url}: #{e.message}"
      title "Error"
      return erb :error
    end

    if !links.include?(profile) and !auth_endpoints.include?(profile) and !gpg_keys.map{|a| a[:href]}.include?(profile)
      @message = "\"#{params[:profile]}\" was not found on the site \"#{params[:me]}\". Try re-scanning after checking your rel=me links on your site."
      title "Error"
      return erb :error
    end

    provider, verified, error_description = verify_user_profile me_parser, profile, me

    if params[:provider] == 'indieauth'
      attempted_username = me
    else
      match = profile.match(Regexp.new Provider.regexes[provider])
      attempted_username = match[1]
    end

    session[:attempted_uri] = me
    session[:attempted_profile] = profile
    session[:attempted_provider] = provider
    session[:attempted_username] = attempted_username
    session[:redirect_uri] = params[:redirect_uri]

    puts "Attempting authentication for #{session[:attempted_uri]} via #{provider} (Expecting #{session[:attempted_username]})"

    if provider == 'indieauth'
      redirect "#{profile}?me=#{me}&scope=#{session[:scope]}&redirect_uri=#{URI.encode_www_form_component(SiteConfig.root+'/auth/indieauth/redirect')}"
    else
      redirect "/auth/#{provider}"
    end
  end

  get '/auth/indieauth/redirect' do 
    # apparently reading the session doesn't initialize it, so we have to modify the session first
    session.delete 'init' 

    puts params.inspect
    puts session.inspect

    # session[:attempted_profile] is the authorization server
    begin
      data = RestClient.post session[:attempted_profile], {
        :state => params[:state],
        :code => params[:code],
        :redirect_uri => "#{SiteConfig.root}/auth/indieauth/redirect"
      }
      puts "Session data"
      puts session.inspect
      puts

      puts "Reply from auth server:"
      puts data.inspect
      puts 


      response = CGI::parse data
      puts "Parsed response"
      puts response.inspect
      puts 

      attempted_token = session[:attempted_token]
      attempted_uri = session[:attempted_uri]
      redirect_uri = session[:redirect_uri]
      attempted_provider = session[:attempted_provider]
      attempted_profile = session[:attempted_profile]

      session[:attempted_profile] = nil
      session[:attempted_provider] = nil
      session[:attempted_profileid] = nil
      session[:attempted_username] = nil
      session[:attempted_token] = nil
      session[:attempted_uri] = nil

      # response['me'] is an array with the user's domain name. double check that's what we expected.
      if response && response['me']
        me = response['me'].first
        if me == attempted_uri
          # Success!
          puts "Successful login (#{me})!"

          redirect_uri = Login.build_redirect_uri({
            :me => me,
            :provider => attempted_provider,
            :profile => attempted_profile,
            :redirect_uri => redirect_uri,
            :state => session[:state],
            :scope => session[:scope]
          })

          puts "Redirecting to #{redirect_uri}"

          return redirect redirect_uri
        else
          @message = "The authorization server replied with me=#{me} but we were expecting #{attempted_uri}"
        end
      else
        @message = "Invalid response from the authorization server"
      end

    rescue => e
      @message = "Something went horribly wrong! I'm sorry, there's not much other information available. You should probably file an issue: https://github.com/aaronpk/IndieAuth.com/issues."
      puts e.inspect
      puts e.backtrace
    end

    title "Error"
    erb :error
  end

  %w(get post).each do |method|
  send(method, '/auth/:name/callback') do
    auth = request.env['omniauth.auth']

    profile = Profile.find :me => session[:attempted_uri], :profile => session[:attempted_profile]
    attempted_username = session[:attempted_username]
    actual_username = ''
    if profile['provider'] == 'google_oauth2'
      authed_url = auth['extra']['raw_info']['profile']
      if authed_url && (match=authed_url.match(Regexp.new Provider.regexes[profile['provider']]))
        actual_username = match[1]
      end
    else
      actual_username = auth['info']['nickname']
    end

    puts "Auth complete!"
    puts "Provider: #{auth['provider']}"
    puts "UID: #{auth['uid']}"
    puts "Username: #{actual_username}"
    # puts "Auth info:"
    # puts auth.inspect
    # puts "Session:"
    # puts session

    if !actual_username || !attempted_username || attempted_username.downcase != actual_username.downcase  # case in-sensitive compare
      @message = "You just authenticated as '#{actual_username}' but your website linked to '#{session[:attempted_profile]}'"
      puts "ERROR: #{@message}"
      title "Error"
      erb :error
    else
      # Authentication succeeded, send them to the client
      redirect_uri = Login.build_redirect_uri({
        :me => session[:attempted_uri],
        :provider => session[:attempted_provider],
        :profile => session[:attempted_profile],
        :redirect_uri => session[:redirect_uri],
        :state => session[:state],
        :scope => session[:scope]
      }, session[:response_type])

      session[:attempted_uri] = nil
      session[:attempted_profileid] = nil
      session[:attempted_provider] = nil
      session[:attempted_username] = nil
      session[:redirect_uri] = nil

      redirect redirect_uri
    end
  end
  end

  get '/auth/failure' do
    @message = "The authentication provider replied with an error: #{params['message']}"
    title "Error"
    erb :error
  end

  get '/success' do
    code = params[:code] || params[:token]

    if code.nil?
      @message = "Missing 'code' parameter"
      title "Error"
      return erb :error
    end

    login = Login.decode_auth_code code

    if login.nil?
      @message = "The code provided was not found"
      title "Error"
      return erb :error
    end

    Log.save login

    @domain = login['me']
    title "Successfully Signed In!"
    erb :success
  end

  get '/reset' do
    session.clear
    title "Session"
    erb :session
  end

end
