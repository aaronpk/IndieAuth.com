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

  def save_user_record(me)
    # Remove trailing "/" when storing and looking up the user
    User.first_or_create :href => me.sub(/(\/)+$/,'')
  end

  def verify_user_profile(me_parser, profile, user)

    # First check if there's already a matching profile record for this user 
    existing = Profile.first :user => user, :href => profile
    puts "Checking for existing profile: #{user.href}, #{profile}"

    if !existing
      # Checks the URL against the list of regexes to see what provider it is
      # Does not fetch the page contents
      profile_parser = RelParser.new profile
      provider = profile_parser.get_provider

      if provider.nil?
        json_error 200, {error: 'unsupported_provider', error_description: 'The specified link is not a supported provider'}
      end

      puts "No existing provider, but parsed as: #{provider.code}"

      # Save the profile entry in the DB, mark as "unverified" if new
      profile_record = Profile.first_or_create({ 
        :user => user, 
        :href => profile
      }, 
      { 
        :provider => provider,
        :verified => false
      })
    else
      profile_parser = RelParser.new profile
      provider = existing.provider
      profile_record = existing
      puts "Found existing: #{provider.code}"
    end

    if provider.code == 'sms' or provider.code == 'email'
      verified = true
      error_description = nil
    elsif provider.code == 'gpg'
      verified = true
      error_description = nil
    elsif provider.code == 'indieauth'
      # Make an HTTP request to the auth server and check that it responds with an "IndieAuth: authorization_endpoint" header
      # But return verified=false if it's actually this server
      # if "#{SiteConfig.root}/auth" == profile
      #   verified = false
      #   error_description = 'This auth server cannot be used to authenticate to itself'
      # else
      #   verified, error_description = me_parser.verify_auth_endpoint profile, profile_parser
      # end
      verified = false
      error_description = 'Support for your own IndieAuth server is coming soon!'
    else
      # This does an HTTP request
      verified, error_description = me_parser.verify_link profile, profile_parser
    end

    if verified
      profile_record.verified = true
      profile_record.active = true
    else
      profile_record.active = false  # Prevent this option from appearing next time the cached list is retrieved
    end
    profile_record.save

    return provider, profile_record, verified, error_description
  end

  def auth_param_setup
    # Double check they provided valid parameters for "me" and "profile"

    me = verify_me_param
    profile = verify_profile_param

    user = save_user_record me

    me_parser = RelParser.new me

    # Don't actually look for *all* links. Just look for the specific one we're looking for in #{profile} and stop there
    if !me_parser.links_to profile
      json_error 200, {error: 'invalid_input', error_description: "\"#{params[:profile]}\" was not found on the site \"#{params[:me]}\""}
    end

    provider, profile_record, verified, error_description = verify_user_profile me_parser, profile, user
    return me, profile, user, provider, profile_record, verified, error_description
  end

  def build_redirect_uri(login)
    puts login.inspect
    if login.redirect_uri
      redirect_uri = URI.parse login.redirect_uri
      p = Rack::Utils.parse_query redirect_uri.query
      p[session[:response_type]] = login.token
      p['me'] = login.user.href
      p['state'] = login.state if login.state
      redirect_uri.query = Rack::Utils.build_query p
      redirect_uri = redirect_uri.to_s 
    else
      redirect_uri = "/success?#{session[:response_type]}=#{login.token}&me=#{URI.encode_www_form_component(login.user.href)}"
      redirect_uri = "#{redirect_uri}&state=#{login.state}" if login.state
    end
    return redirect_uri
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
    # If there's already a user record, look up all their existing profiles
    @user = User.first :href => @me.sub(/(\/)+$/,'')
    unless @user.nil?
      @profiles = @user.profiles.all(:active => true)
    end

    save_response_type
    session[:state] = params[:state]
    session[:scope] = params[:scope]

    @redirect_uri = params[:redirect_uri]
    @client_id = params[:client_id]
    @state = params[:state]
    @scope = params[:scope]
    @providers = Provider.all(:home_page.not => '')

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

    # Pre-generate the GPG challenge if there is already a user record and GPG profile
    @gpg_challenges = []
    if @user
      profiles = @user.profiles.all(:provider => Provider.first(:code => 'gpg'), :active => 1)
      profiles.each do |profile|
        @gpg_challenges << {
          :profile => profile.href,
          :challenge => generate_gpg_challenge(@me, @user, profile, params)
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

    user = save_user_record me

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

    # Save the complete list of links to the user object
    user.me_links = links.to_json

    # Check if the website points to its own IndieAuth server
    auth_endpoints = []
    begin
      auth_endpoints = find_auth_endpoints me_parser
    rescue Exception => e
      json_error 200, {error: 'unknown', error_description: "Unknown error retrieving #{me_parser.url}: #{e.message}"}
    end

    # Save the auth endpoint (will delete any existing ones if none was found now)
    user.auth_endpoints = auth_endpoints.to_json

    gpg_keys = []
    begin
      gpg_keys = get_gpg_keys me_parser
    rescue Exception => e
      json_error 200, {error: 'unknown', error_description: "Unknown error retrieving GPG keys for #{me_parser.url}: #{e.message}"}
    end

    user.gpg_keys = gpg_keys.to_json

    user.last_refresh_at = DateTime.now
    user.save

    # Delete all old profiles that aren't linked on the user's page anymore
    # Except totp!
    user.profiles.each do |profile|
      if profile.active and !['totp','server'].include? profile.provider.code and !links.include? profile.href
        puts "Link to #{profile.href} no longer found, deactivating"
        profile.active = false
        profile.save
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
      provider = profile_parser.get_provider

      if provider && (provider.code == 'sms' or provider.code == 'email')
        verified = true
        # Run verify_user_profile which will save the profile in the DB. Since it's only
        # running for SMS and Email profiles, it won't trigger an HTTP request.
        verify_user_profile me_parser, link, user
      end

      links_response << {
        profile: link,
        provider: (provider ? provider.code : nil),
        verified: verified
      }
    end

    if user.auth_endpoints 
      provider = Provider.first(:code => 'indieauth')

      JSON.parse(user.auth_endpoints).each do |endpoint|
        # Save the profile in the DB
        profile = Profile.first_or_create({ 
          :user => user, 
          :href => endpoint
        }, 
        { 
          :provider => provider,
          :verified => false
        })
        profile.active = true
        profile.save

        links_response << {
          profile: endpoint,
          provider: 'indieauth',
          verified: nil
        }
      end
    end

    if user.gpg_keys
      provider = Provider.first(:code => 'gpg')

      JSON.parse(user.gpg_keys).each do |key|
        profile = Profile.first_or_create({
          :user => user,
          :href => key['href'],
          :provider => provider
        }, {
          :verified => true
        })
        profile.active = true
        profile.save

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
      me, profile, user, provider, profile_record, verified, error_description = auth_param_setup
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
      provider: provider.code, 
      verified: verified,
      error_description: error_description,
      auth_path: (verified ? profile_record.auth_path : false)
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

    user = save_user_record me

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

    provider, profile_record, verified, error_description = verify_user_profile me_parser, profile, user

    session[:attempted_uri] = me
    session[:attempted_userid] = user[:id]

    match = profile_record.href.match(Regexp.new provider['regex_username'])
    session[:attempted_username] = match[1]

    login = Login.create :user => user,
      :provider => provider,
      :profile => profile_record, 
      :complete => false,
      :token => Login.generate_token,
      :redirect_uri => params[:redirect_uri],
      :state => session[:state],
      :scope => session[:scope]

    session[:attempted_token] = login[:token]
    session[:attempted_profile] = profile
    puts "Attempting authentication for #{session[:attempted_uri]} via #{provider['code']} (Expecting #{session[:attempted_username]})"

    if params[:openid_url]
      redirect "/auth/#{provider.code}?openid_url=#{session[:me]}" # TODO: verify this works
    elsif provider.code == 'indieauth'
      redirect "#{profile_record.href}?me=#{me}&scope=#{session[:scope]}&redirect_uri=#{URI.encode_www_form_component 'https://indieauth.cc/auth/indieauth/callback'}"
    else
      redirect "/auth/#{provider.code}"
    end
  end

  %w(get post).each do |method|
  send(method, '/auth/:name/callback') do
    auth = request.env['omniauth.auth']

    profile = Profile.first :user_id => session[:attempted_userid], :href => session[:attempted_profile]
    attempted_username = session[:attempted_username]
    actual_username = ''
    if profile.provider[:code] == 'google_oauth2'
      authed_url = auth['extra']['raw_info']['link']
      if authed_url && (match=authed_url.match(Regexp.new profile.provider[:regex_username]))
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
      token = session[:attempted_token]
      login = Login.first :token => token

      session[:attempted_userid] = nil
      session[:attempted_profile] = nil
      session[:attempted_username] = nil
      session[:attempted_token] = nil

      if login.nil?
        @message = "Something went horribly wrong!"
        title "Error"
        erb :error
      else
        login.complete = true
        login.save
        redirect build_redirect_uri login
      end
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

    login = Login.first :token => code

    if login.nil?
      @message = "The code provided was not found"
      title "Error"
      return erb :error
    end

    login.last_used_at = Time.now
    login.used_count = login.used_count + 1
    login.save

    @domain = login.user['href']
    title "Successfully Signed In!"
    erb :success
  end

  get '/reset' do
    session.clear
    title "Session"
    erb :session
  end

end