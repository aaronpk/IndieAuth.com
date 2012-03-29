class Controller < Sinatra::Base
  before do 
    session[:null] = true   # weird hack to make the session object populate???
  end

  get '/?' do
    erb :index
  end

  get '/auth' do 
    session.clear
    session[:redirect_uri] = params[:redirect_uri]

    if params[:me].nil?
      @error = "Parameter 'me' should be set to your domain name"
      erb :error
    else
      # Parse the incoming "me" link looking for all rel=me URLs
      me = params[:me]
      me = "http://#{me}" unless me.start_with?('http')
    
      parser = RelParser.new me
      @links = parser.get_supported_links

      if @links.length == 0
        erb :error_no_links
      else
        link = @links.first 
        meURI = URI.parse me
        session[:attempted_domain] = meURI.host
        session[:attempted_username] = parser.username_for_url link
        provider_name = parser.provider_name_for_url link
        puts "Attempting authentication for #{session[:attempted_username]} via #{provider_name}"
        redirect "/auth/#{provider_name}"
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
      if session[:redirect_uri]
        token = "GUEUHKSFHEOJSDKJGHKSEJRHKUHSEIURH"
        redirect "#{session[:redirect_uri]}?token=#{token}"
      else
        redirect "/success"
      end
    end
  end

  get '/success' do
    @domain = session[:domain]
    erb :success
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

end
