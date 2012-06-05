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

  get '/auth' do 
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
                :provider => provider 
              }, 
              { 
                :href => link[:link],
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
    puts "Auth complete!"
    puts "Provider: #{auth['provider']}"
    puts "UID: #{auth['uid']}"
    puts "Username: #{auth['info']['nickname']}"
    puts session

    profile = Profile.first :user_id => session[:attempted_userid], :href => session[:attempted_provider_uri]
    if profile.provider[:code] == 'open_id'
      actual_username = params['openid_url']
    else
      actual_username = auth['info']['nickname']
    end

    if session[:attempted_username].downcase != actual_username.downcase  # case in-sensitive compare
      @message = "You just authenticated as #{actual_username} but your website linked to #{session[:attempted_provider_uri]}"
      title "Error"
      erb :error
    else
      session[params[:name]] = actual_username
      session[:domain] = session[:attempted_domain]
      session[:attempted_username] = nil
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
      return json_error 400, {:error => "invalid_request", :error_description => "Missing 'token' parameter"}
    end

    login = Login.first :token => params[:token]
    if login.nil?
      return json_error 404, {:error => "invalid_token", :error_description => "The token provided was not found"}
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
