class Controller < Sinatra::Base
  before do 
    if request.path != "/session" # don't set sessions for JSON api requests
      session[:null] = true   # weird hack to make the session object populate???
    end
    @site = Site.first_or_create :domain => request.host
  end

  get '/?' do
    title "IndieAuth - Sign in with your domain name"
    erb :index
  end

  get '/setup/?' do
    title "IndieAuth Documentation - Sign in with your domain name"
    erb :setup_instructions
  end

  # 1. Begin the auth process
  get '/auth' do
    title "IndieAuth - Sign in with your domain name"
    erb :auth
  end

  # 2. Return all rel=me links on the given page
  # Params: 
  #  * me=example.com
  get '/auth/relme_links.json' do
    me = params[:me]

    # Prepend "http" unless it's already there
    me = "http://#{me}" unless me.start_with?('http')

    # Remove trailing "/" when storing and looking up the user
    user = User.first_or_create :href => me.sub(/(\/)+$/,'')
    parser = RelParser.new me

    begin
      links = parser.rel_me_links
    rescue SocketError
      return json_error 200, {error: 'connection_error', error_description: "Error retrieving: #{me}"}
    end

    if links.nil?
      return json_error 200, {error: 'no_links_found', error_description: "No links found on #{me} or could not parse the page"}
    end

    # Save the complete list of links to the user object
    user.me_links = links.to_json
    user.save

    json_response 200, {links: links}
  end

  # 3. Verify a link has a rel=me relation back to the specified site
  # Params:
  #  * me=example.com
  #  * profile=provider.com/user/xxxxx
  get '/auth/verify_link.json' do
    me = params[:me]
    profile = params[:profile]

    return json_error(400, {error: 'missing_param', error_description: 'parameter "profile" is required'}) if params[:profile].nil?

    # Prepend "http" unless it's already there
    me = "http://#{me}" unless me.start_with?('http')

    # Remove trailing "/" when storing and looking up the user
    user = User.first_or_create :href => me.sub(/(\/)+$/,'')

    parser = RelParser.new me

    # Find all the rel=me links on the specified page
    begin
      links = parser.rel_me_links
    rescue SocketError
      return json_error 200, {error: 'connection_error', error_description: "Error retrieving: #{me}"}
    end

    if links.nil?
      return json_error 200, {error: 'no_links_found', error_description: "No links found on #{me} or could not parse the page"}
    end

    if !links.include?(profile)
      return json_error 400, {error: 'invalid_input', error_description: 'parameter "profile" must be one of the rel=me links in the site specified in the "me" parameter'}
    end

    # Search the "profile" page for a rel=me link back to "me"
    profile_parser = RelParser.new profile

    provider = profile_parser.get_provider

    if provider.nil?
      return json_error 200, {error: 'unsupported_provider', error_description: 'The specified link is not a supported provider'}
    end

    # Save the profile entry in the DB as "unverified"
    user_profile = Profile.first_or_create({ 
      :user => user, 
      :href => profile
    }, 
    { 
      :provider => provider,
      :verified => false
    })

    verified = parser.verify_link profile, profile_parser

    if verified
      user_profile.verified = true
      user_profile.save
    end

    puts verified.inspect

    if false # TODO: if provider is openid
      auth_path = "/auth/open_id?openid_url=#{profile}"
    else
      auth_path = "/auth/#{provider.code}"
    end

    json_response 200, {
      me: me, 
      profile: profile, 
      provider: provider.code, 
      verified: verified,
      auth_path: auth_path
    }
  end

  get '/auth-old' do 
    session.clear
    session[:redirect_uri] = params[:redirect_uri]

    if params[:me].nil?
      title "Error"
      @message = "Parameter 'me' should be set to your domain name"
      erb :error
    else
      # Parse the incoming "me" link looking for all rel=me URLs
      me = params[:me]

      # Prepend "http" unless it's already there
      me = "http://#{me}" unless me.start_with?('http')

      # Add trailing "/"
      # meURI = URI.parse me
      # if meURI.path == ""
      #   meURI.path = "/" 
      #   me = meURI.to_s
      # end

      session[:attempted_uri] = me

      # Remove trailing "/" when storing and looking up the user
      user = User.first_or_create :href => me.sub(/(\/)+$/,'')

      # Check if the entered URL is a known auth provider
      # This will also do an HTTP lookup to find OpenID delegate links
      parser = RelParser.new me
      begin
        @provider = parser.get_provider
      rescue SocketError
        @message = "Error retrieving: #{me}"
        title 'Error'
        return erb :error
      end

      # If not, find all rel=me links and look for known providers
      if @provider.nil?
        begin
          links = parser.rel_me_links
        rescue SocketError
          @message = "Error retrieving: #{me}"
          title 'Error'
          return erb :error
        end

        if links.nil?
          @message = "No links found on #{me} or could not parse the page"
          title 'Error'
          return erb :error
        end

        # Save the complete list of links to the user object
        user.me_links = links.to_json
        user.save

        if links.length == 0
          @link = false
        else
          # Filter only the links we support, and save unverified "profile" records for them
          links = parser.get_supported_links
          puts "Supported links: "
          puts links.collect {|c| c[:link]}

          selected_profile = nil

          links.each do |link|
            provider = link[:parser].get_provider
            verified = parser.verify_link link[:link], link[:parser]
            if provider
              profile = Profile.first_or_create({ 
                :user => user, 
                :href => link[:link]
              }, 
              { 
                :provider => provider,
                :verified => verified
              })

              # Use the first verified profile as the selected profile for auth
              if verified
                if selected_profile.nil?
                  selected_profile = profile
                end
              end
            end
          end

          @profile = selected_profile
          if @profile.nil?
            @message = "No valid authentication providers were found at #{me}"
            title "Error"
            return erb :error
          end

          @provider = @profile.provider
          @link = @profile.href

          puts "Found valid provider: #{@provider['code']}"
        end
      else
        # If "me" is one of our OAuth providers, use it directly
        @link = me
        @profile = Profile.first_or_create({
          :user => user,
          :provider => @provider
        }, 
        {
          :href => me,
          :verified => true
        })
      end

      if !@link
        @message = 'No rel="me" links were found on your website'
        title "Error"
        erb :error
      else
        # Now that we got here, we have verified the two sites link to each other. Now we just need
        # to authenticate the user with the provider to make sure they are who they say they are.
        puts "Provider: #{@provider}"
        puts "Profile: #{@profile}"
        puts "User: #{user}"

        login = Login.create :user => user, 
          :provider => @provider, 
          :profile => @profile, 
          :complete => false,
          :token => Login.generate_token,
          :redirect_uri => params[:redirect_uri]

        session[:attempted_userid] = user[:id]
        session[:attempted_token] = login[:token]
        session[:attempted_username] = @provider.username_for_url @link
        session[:attempted_provider_uri] = @link
        puts "Attempting authentication for #{session[:attempted_username]} via #{@provider['code']}"

        if @provider['code'] == 'open_id'
          redirect "/auth/#{@provider['code']}?openid_url=#{@profile[:href]}"
        else
          redirect "/auth/#{@provider['code']}"
        end
      end
    end
  end

  %w(get post).each do |method|
  send(method, '/auth/:name/callback') do
    auth = request.env['omniauth.auth']

    profile = Profile.first :user_id => session[:attempted_userid], :href => session[:attempted_provider_uri]
    if profile.provider[:code] == 'open_id'
      attempted_username = session[:attempted_username]
      actual_username = params['openid_url']
    elsif profile.provider[:code] == 'google_oauth2'
      attempted_username = session[:attempted_provider_uri]
      actual_username = auth['extra']['raw_info']['link']
    else
      attempted_username = session[:attempted_username]
      actual_username = auth['info']['nickname']
    end

    puts "Auth complete!"
    puts "Provider: #{auth['provider']}"
    puts "UID: #{auth['uid']}"
    puts "Username: #{actual_username}"
    puts "Auth info:"
    puts auth.inspect
    puts "Session:"
    puts session

    if !actual_username || !attempted_username || attempted_username.downcase != actual_username.downcase  # case in-sensitive compare
      @message = "You just authenticated as '#{actual_username}' but your website linked to '#{attempted_username}'"
      title "Error"
      erb :error
    else
      session[params[:name]] = actual_username
      session[:domain] = session[:attempted_domain]
      session[:attempted_username] = nil
      session[:attempted_provider_uri] = nil
      session[:attempted_domain] = nil
      session[:logged_in] = 1

      token = session[:attempted_token]
      login = Login.first :token => token

      if login.nil?
        @message = "Something went horribly wrong!"
        title "Error"
        erb :error
      else
        login.complete = true
        login.save
        if session[:redirect_uri]
          redirect_uri = URI.parse session[:redirect_uri]
          params = Rack::Utils.parse_query redirect_uri.query
          params['token'] = token
          redirect_uri.query = Rack::Utils.build_query params
          redirect redirect_uri.to_s
        else
          redirect "/success?token=#{token}"
        end
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
    if params[:token].nil?
      @message = "Missing 'token' parameter"
      title "Error"
      return erb :error
    end

    login = Login.first :token => params[:token]

    if login.nil?
      @message = "The token provided was not found"
      title "Error"
      return erb :error
    end

    @domain = login.user['href']
    title "Successfully Signed In!"
    erb :success
  end

  get '/session' do
    if params[:token].nil?
      return json_error 400, {error: "invalid_request", error_description: "Missing 'token' parameter"}
    end

    login = Login.first :token => params[:token]
    if login.nil?
      return json_error 404, {error: "invalid_token", error_description: "The token provided was not found"}
    end

    login.last_used_at = Time.now
    login.used_count = login.used_count + 1
    login.save

    json_response 200, {:me => login.user['href']}
  end

  get '/reset' do
    session.clear
    title "Session"
    erb :session
  end

  # get '/session' do 
  #   @session = session
  #   puts session
  #   title "Session"
  #   erb :session
  # end

  def json_error(code, data)
    return [code, {
        'Content-Type' => 'application/json;charset=UTF-8',
        'Cache-Control' => 'no-store'
      }, 
      data.to_json]
  end

  def json_response(code, data)
    return [code, {
        'Content-Type' => 'application/json;charset=UTF-8',
        'Cache-Control' => 'no-store'
      }, 
      data.to_json]
  end

end
