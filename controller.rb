class Controller < Sinatra::Base
  before do 
    session[:null] = true
  end

  get '/?' do
    erb :index
  end

  get '/login' do 
    session[:redirect_uri] = params[:redirect_uri]

    if params[:me].nil?
      @error = "Parameter 'me' is required"
      erb :error
    else
      # Parse the incoming "me" link looking for all rel=me URLs
      me = params[:me]
      me = "http://#{me}" unless me.start_with?('http')
    
      parser = RelParser.new me

      @session = session
      erb :session
    end
  end

  get '/test' do
    if params[:me].nil?
      @error = "Parameter 'me' is required"
      erb :error
    else
      # Parse the incoming "me" link looking for all rel=me URLs
      me = params[:me]
      me = "http://#{me}" unless me.start_with?('http')
      meURI = URI.parse me
    
      # Normalize
      meURI.scheme = "http" if meURI.scheme == "https"
      meURI.path = "/" if meURI.path == ""

      parser = RelParser.new me
      links = parser.get "me"
      @links = []
      links.each do |link|

        # Scan the external site for rel="me" links
        site_parser = RelParser.new link
        site_links = site_parser.get "me"
        links_back = false
        # Find any that match the user's entered "me" link

        site_links.each do |site_link|
          siteURI = URI.parse site_link
          # Normalize
          siteURI.scheme = "http" if siteURI.scheme == "https"
          siteURI.path = "/" if siteURI.path == ""

          # Compare
          if siteURI.scheme == meURI.scheme && 
            siteURI.host == meURI.host &&
            siteURI.path == meURI.path
            links_back = true
          end
        end

        @links << {
          :url => link,
          :me_links => site_links,
          :links_back => links_back
        }
      end

      erb :results
    end
  end

  get '/session' do 
    @session = session
    puts session
    erb :session
  end

  get '/auth/:name/callback' do
    auth = request.env['omniauth.auth']
    puts "Auth complete!"
    puts auth
    session[params[:name]] = auth
    session[:logged_in] = 4
    @session= session
    erb :session
  end

end
