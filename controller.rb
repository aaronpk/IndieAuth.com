class Controller < Sinatra::Base
  before do 
    session[:null] = true   # weird hack to make the session object populate???
    @site = Site.first_or_create :domain => request.host
  end

  get '/?' do
    erb :index
  end

  get '/auth' do 
    session.clear
    session[:redirect_uri] = params[:redirect_uri]

    if params[:me].nil?
      @message = "Parameter 'me' should be set to your domain name"
      erb :error
    else
      # Parse the incoming "me" link looking for all rel=me URLs
      me = params[:me]
      me = "http://#{me}" unless me.start_with?('http')

      session[:attempted_uri] = me

      user = User.first_or_create :href => me

      # Check if the entered URL is a known OAuth provider
      @provider = Provider.provider_for_url me

      # If not, find all rel=me links and look for known providers
      if @provider.nil?
        parser = RelParser.new me
        links = parser.rel_me_links

        # Save the complete list of links to the user object
        user.me_links = links.to_json
        user.save

        if links.length == 0
          @link = false
        else
          # Filter only the links we support, and save unverified "profile" records for them
          links = parser.get_supported_links
          puts "Supported links: #{links}"
          links.each do |link|
            provider = Provider.provider_for_url(link)
            profile = Profile.first_or_create({ 
              :user => user, 
              :provider => provider 
            }, 
            { 
              :href => link 
            })
          end
          # Find a provider that has a rel="me" link back to the user's profile
          links.each do |link|
            provider = Provider.provider_for_url(link)
            verified = parser.verify_link link
            if verified
              @profile = Profile.first :user => user, :provider => provider
              @profile.verified = true
              @profile.save
              @provider = provider
              @link = link
              break
            end
          end
          puts "Found valid provider: #{@provider['code']}"
        end
      else
        # If "me" is one of our OAuth providers, use it directly
        @link = me
      end

      if !@link
        erb :error_no_links
      else
        puts "Provider: #{@provider}"
        puts "Profile: #{@profile}"
        puts "User: #{user}"

        login = Login.create :user => user, 
          :provider => @provider, 
          :profile => @profile, 
          :complete => false,
          :token => Login.generate_token,
          :redirect_uri => params[:redirect_uri]

        session[:attempted_token] = login[:token]
        session[:attempted_username] = @provider.username_for_url @link
        puts "Attempting authentication for #{session[:attempted_username]} via #{@provider['code']}"
        redirect "/auth/#{@provider['code']}"
      end
    end
  end

  get '/auth/:name/callback' do
    auth = request.env['omniauth.auth']
    puts "Auth complete!"
    puts "Provider: #{auth['provider']}"
    puts "UID: #{auth['uid']}"
    puts "Username: #{auth['info']['nickname']}"
    puts session

    if session[:attempted_username] != auth['info']['nickname']
      @attempted_username = session[:attempted_username]
      @actual_username = auth['info']['nickname']
      erb :error_bad_user
    else
      session[params[:name]] = auth['info']['nickname']
      session[:domain] = session[:attempted_domain]
      session[:attempted_username] = nil
      session[:attempted_domain] = nil
      session[:logged_in] = 1

      token = session[:attempted_token]
      login = Login.first :token => token
      login.complete = true
      login.save

      if login.nil?
        @message = "Login attempt not found"
        erb :error
      else
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

  get '/auth/failure' do
    @message = params['message']
    erb :error
  end

  get '/success' do
    @domain = session[:domain]
    erb :success
  end

  get '/session/:token' do
    if params[:token].nil?
      return json_error 400, {:error => "Parameter 'token' is required"}
    end

    login = Login.first :token => params[:token]
    if login.nil?
      return json_error 404, {:error => "Token not found"}
    end

    json_response 200, {:me => login.user['href']}
  end

  get '/test' do
    if params[:me].nil?
      @error = "Parameter 'me' is required"
      erb :error
    else
      # Parse the incoming "me" link looking for all rel=me URLs
      me = params[:me]
      me = "http://#{me}" unless me.start_with?('http')

      parser = RelParser.new me
      @links = parser.get_supported_links
      puts @links

      erb :results
    end
  end

  get '/reset' do
    session.clear
    erb :session
  end

  get '/session' do 
    @session = session
    puts session
    erb :session
  end

  def json_error(code, data)
    halt code, data.to_json
  end

  def json_response(code, data)
    halt code, data.to_json
  end

end
