class Controller < Sinatra::Base

  def normalize_me(me)
    begin
      uri = Addressable::URI.parse me

      # Bare domains get parsed as just a relative path, so fix that here
      if uri.scheme.nil? and uri.host.nil? and !uri.path.nil?
        host = uri.path
        uri.path = '/'
        uri.host = host
      end

      if uri.scheme.nil?
        # If there is no scheme, first try HTTPS and fall back to HTTP if that doesn't work
        tmp = uri
        tmp.scheme = 'https'
        begin
          response = HTTParty.head tmp.normalize.to_s, {
            :timeout => 6
          }
          uri.scheme = 'https'
        rescue => e
          uri.scheme = 'http'
        end
      end

      if !uri.host.nil? and ['http','https'].include? uri.scheme
        return uri.normalize.to_s
      end
    rescue
    end

    return nil
  end

  def verify_me_param
    me = params[:me]

    if me.nil? || me == ""
      json_error 200, {error: 'invalid_input', error_description: 'parameter "me" is required'}
    end

    me = normalize_me me

    if me.nil?
      json_error 200, {error: 'invalid_input', error_description: 'invalid value for me, must be a URL'}
    else
      me
    end
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

    if provider == 'email'
      verified = true
      error_description = nil
    elsif provider == 'gpg'
      verified = true
      error_description = nil
    elsif provider == 'indieauth'
      if "#{SiteConfig.root}/auth" == profile
        verified = false
        error_description = 'This auth server cannot be used to authenticate to itself'
      else
        verified = true
      end
    else
      # This does an HTTP request
      puts "::=> verifying link"
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

    title "Sign in with your domain name"
    @me = params[:me]

    if @me.nil?
      title "Web Sign-In"
      halt 200, {
        'IndieAuth' => 'authorization_endpoint'  # tell clients this is an indieauth endpoint
      }, erb(:sign_in)
    end

    @me = normalize_me @me

    if @me.nil?
      @error_title = "Invalid \"me\" value"
      @message = "Your identifier must be a valid URL."
      @error_details = "The value provided was:<br><code>#{CGI.escapeHTML params[:me]}</code>"
      halt 400, erb(:error)
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
    session[:redirect_uri] = URI.encode params[:redirect_uri]

    @redirect_uri = params[:redirect_uri]
    @client_id = params[:client_id]
    @state = params[:state]
    @scope = params[:scope]

    @app_name = 'Unknown App'
    @app_logo = nil

    if params[:client_id]
      # Check for valid client ID. Must be either a URL or a string
      valid = false
      begin
        client_id = URI.parse params[:client_id]
        if ['http','https'].include? client_id.scheme and client_id.host
          valid = true
        end
      rescue
      end

      if !valid
        @error_title = "Invalid client_id"
        @message = "The client_id must be a valid URL."
        @error_details = "The client_id provided was:<br><code>#{CGI.escapeHTML params[:client_id]}</code>"
        halt 400, erb(:error)
      end

      # Remove visible http and trailing slash from the display name
      @app_name = display_url params[:client_id]
      # Look for an h-card on the URL indicated by the client_id
      begin
        client_id = URI.parse params[:client_id]
        if ['https','http'].include? client_id.scheme and !client_id.host.nil?
          client_id.path = '/' if client_id.path == ''

          # Fetch the HTML
          response = HTTParty.get client_id, {
            # For testing slow connections, use https://www.npmjs.com/package/crapify and set it as a proxy
            # :http_proxyaddr => "localhost",
            # :http_proxyport => 5000,
            :timeout => 3
          }

          client = Microformats2.parse response.body
          if client.x_app.name
            @app_name = client.x_app.name
          end
          if client.x_app.logo
            @app_logo = client_id + URI.parse(client.x_app.logo.to_s)
          end
        end
      rescue => e
        puts "Error retrieving client_id: #{e.message}"
      end

    elsif params[:redirect_uri]
      @app_name = display_url params[:redirect_uri]
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

    # If only one profile is set, and it's an indieauth authorization endpoint, then skip directly to it
    if @profiles.length == 1 && @profiles[0]['provider'] == 'indieauth'
      profile = @profiles[0]
      redirect Provider.auth_path(profile['provider'], profile['href'], @me), 302
    else
      halt 200, {
        'IndieAuth' => 'authorization_endpoint'
      }, erb(:auth)
    end
  end

  # 2. Return all supported providers on the given page
  # Params:
  #  * me=example.com
  get '/auth/supported_providers.json' do
    me = verify_me_param

    me_parser = RelParser.new me

    # Delete all cached providers
    Profile.delete_profile me

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
      if data['provider'] == 'indieauth'
        if !auth_endpoints.include? profile
          puts "Link to IndieAuth server #{profile} no longer found, deactivating"
          Profile.delete :me => me, :profile => profile
        end
      elsif data['provider'] == 'gpg'
        if !gpg_keys.map{|k| k[:href]}.include? profile
          puts "Link to GPG key #{profile} no longer found, deactivating"
          Profile.delete :me => me, :profile => profile
        end
      else
        if !links.include? profile
          puts "Link to #{profile} no longer found, deactivating"
          Profile.delete :me => me, :profile => profile
        end
      end
    end

    # Check each link to see if it's a supported provider
    links_response = []

    links.each do |link|
      verified = nil

      # Checks the URL against the list of regexes to see what provider it is
      # Does not fetch the page contents
      profile_parser = RelParser.new link
      provider = Provider.provider_for_url link

      if provider && ['email'].include?(provider)
        verified = true
        # Run verify_user_profile which will save the profile in the DB. Since it's only
        # running for Email profiles, it won't trigger an HTTP request.
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
        if "#{SiteConfig.root}/auth" != endpoint
          Profile.save({:me => me, :profile => endpoint}, {:provider => 'indieauth', :created_at => Time.now.to_i})
          links_response << {
            profile: endpoint,
            provider: 'indieauth',
            verified: true,
            auth_path: Provider.auth_path(provider, endpoint, me)
          }
        end
      end
    end

    if gpg_keys.length > 0
      provider = 'gpg'

      gpg_keys.each do |key|
        # Store it now because when we verify it with the verify_link.json request, it doesn't know what provider it is and this will tell it
        Profile.save({:me => me, :profile => key[:href]}, {:provider => 'gpg', :created_at => Time.now.to_i})
        links_response << {
          profile: key[:href],
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
      error: (error_description ? true : false),
      error_description: error_description,
      auth_path: (verified ? Provider.auth_path(provider, profile, me) : false)
    }

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

    # TODO: if the user had only one auth endpoint and they were redirected here skipping the prompt,
    # then we need to clear the cache and re-check for an endpoint for them.
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
    session[:localstate] = SecureRandom.hex # generate a state value that will be checked on the redirect

    puts "Attempting authentication for #{session[:attempted_uri]} via #{provider} (Expecting #{session[:attempted_username]})"

    if provider == 'indieauth'
      query = {
        me: me,
        scope: session[:scope],
        client_id: "#{SiteConfig.root}/",
        redirect_uri: "#{SiteConfig.root}/auth/indieauth/redirect",
        state: session[:localstate]
      }
      query_string = URI.encode_www_form query
      redirect "#{profile}?#{query_string}", 302
    else
      redirect "/auth/#{provider}", 302
    end
  end

  get '/auth/indieauth/redirect' do
    # apparently reading the session doesn't initialize it, so we have to modify the session first
    session.delete 'init'

    if session[:attempted_profile].nil?
      return redirect '/'
    end

    title "Error"

    # Check that the redirect includes the state parameter we set
    if !params[:state]
      @message = "The authorization server did not include the state parameter in the redirect"
      return erb :error
    end

    if params[:state] != session[:localstate]
      @message = "The authorization server returned a state value that did not match"
      return erb :error
    end

    puts params.inspect
    puts session.inspect

    # session[:attempted_profile] is the authorization server
    begin
      data = RestClient.post session[:attempted_profile], {
        :code => params[:code],
        :client_id => "#{SiteConfig.root}/",
        :redirect_uri => "#{SiteConfig.root}/auth/indieauth/redirect"
      }, :accept => 'application/json'
      puts "Session data"
      puts session.inspect
      puts

      puts "Reply from auth server:"
      puts data.inspect
      puts

      # Only parse as JSON if the response looks like JSON
      # This maintains fallback behavior of expecting form-encoded responses even if the server ignores the Accept header
      if data[0] == '{'
        response = JSON.parse data
      else
        response = CGI::parse data
      end
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
        if response['me'].kind_of?(Array)
          me = response['me'].first
        else
          me = response['me']
        end
        # Allow the response to indicate a different user, only if it's on the same domain as we were expecting
        meURI = URI.parse me
        attemptedURI = URI.parse attempted_uri

        if meURI.host == attemptedURI.host
          # Success!
          redirect_uri = Login.build_redirect_uri({
            :me => me,
            :provider => attempted_provider,
            :profile => attempted_profile,
            :redirect_uri => redirect_uri,
            :state => session[:state],
            :scope => session[:scope]
          })
          puts "Successful login (#{me}) redirecting to #{redirect_uri}"

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

    if session[:attempted_profile].nil?
      return redirect '/'
    end

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

      puts "Successful login (#{session[:attempted_uri]}) redirecting to #{redirect_uri}"

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
