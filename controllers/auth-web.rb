class Controller < Sinatra::Base


  def verify_me_param
    me = params[:me]

    if me.nil? || me == ""
      json_error 400, {error: 'invalid_input', error_description: 'parameter "me" is required'}
    end

    # Prepend "http" unless it's already there
    me = "http://#{me}" unless me.start_with?('http')
    me
  end

  def verify_profile_param
    profile = params[:profile]

    if profile.nil? || profile == ""
      json_error 400, {error: 'invalid_input', error_description: 'parameter "profile" is required'}
    end

    profile
  end

  def find_all_relme_links(me_parser, profile=nil)
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

  def save_user_record(me)
    # Remove trailing "/" when storing and looking up the user
    User.first_or_create :href => me.sub(/(\/)+$/,'')
  end

  def verify_user_profile(me_parser, profile, user)

    # Checks the URL against the list of regexes to see what provider it is
    # Does not fetch the page contents
    profile_parser = RelParser.new profile
    provider = profile_parser.get_provider

    if provider.nil?
      json_error 200, {error: 'unsupported_provider', error_description: 'The specified link is not a supported provider'}
    end

    # Save the profile entry in the DB as "unverified"
    profile_record = Profile.first_or_create({ 
      :user => user, 
      :href => profile
    }, 
    { 
      :provider => provider,
      :verified => false
    })

    if provider.code == 'sms' or provider.code == 'email'
      verified = true
      error_description = nil
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
      json_error 400, {error: 'invalid_input', error_description: 'parameter "profile" must be one of the rel=me links in the site specified in the "me" parameter'}
    end

    provider, profile_record, verified, error_description = verify_user_profile me_parser, profile, user
    return me, profile, user, provider, profile_record, verified, error_description
  end

  def build_redirect_uri(login)
    if login.redirect_uri
      redirect_uri = URI.parse login.redirect_uri
      p = Rack::Utils.parse_query redirect_uri.query
      p['token'] = login.token
      p['me'] = login.user.href
      redirect_uri.query = Rack::Utils.build_query p
      redirect_uri = redirect_uri.to_s 
    else
      redirect_uri = "/success?token=#{login.token}&me=#{URI.encode_www_form_component(login.user.href)}"
    end
    return redirect_uri
  end

  # 1. Begin the auth process
  get '/auth' do
    title "IndieAuth - Sign in with your domain name"
    @me = params[:me]

    if @me.nil?
      @message = 'No "me" value was specified'
      title "Error"
      return erb :error      
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

    @redirect_uri = params[:redirect_uri]
    @providers = Provider.all(:home_page.not => '')
    erb :auth
  end

  # 2. Return all rel=me links on the given page
  # Params: 
  #  * me=example.com
  get '/auth/relme_links.json' do
    me = verify_me_param

    user = save_user_record me

    me_parser = RelParser.new me

    links = find_all_relme_links me_parser

    # Save the complete list of links to the user object
    user.me_links = links.to_json
    user.last_refresh_at = DateTime.now
    user.save

    # Delete all old profiles that aren't linked on the user's page anymore
    # Except totp!
    user.profiles.each do |profile|
      if !['totp','server'].include? profile.provider.code and !links.include? profile.href
        puts "Link to #{profile.href} no longer found, deactivating"
        profile.active = false
        profile.save
      end
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

    json_response 200, {links: links_response}
  end

  # 3. Verify a link has a rel=me relation back to the specified site
  # Params:
  #  * me=example.com
  #  * profile=provider.com/user/xxxxx
  get '/auth/verify_link.json' do
    me, profile, user, provider, profile_record, verified, error_description = auth_param_setup

    if false # TODO: if provider is openid
      auth_path = "/auth/start?openid_url=#{profile}&me=#{me}"
    else
      auth_path = "/auth/start?me=#{URI.encode_www_form_component me}&profile=#{URI.encode_www_form_component profile}"
    end

    json_response 200, {
      me: me, 
      profile: profile, 
      provider: provider.code, 
      verified: verified,
      error_description: error_description,
      auth_path: (verified ? auth_path : false)
    }
  end

  get '/auth/start' do

    # TODO: handle these errors differently by redirecting to an error page instead of returning JSON
    me = verify_me_param
    profile = verify_profile_param

    user = save_user_record me

    me_parser = RelParser.new me

    links = find_all_relme_links me_parser

    if !links.include?(profile)
      @message = 'Parameter "profile" must be one of the rel=me links in the site specified in the "me" parameter'
      title "Error"
      return erb :error
    end

    provider, profile_record, verified, error_description = verify_user_profile me_parser, profile, user

    session[:attempted_uri] = me
    session[:attempted_userid] = user[:id]

    login = Login.create :user => user,
      :provider => provider,
      :profile => profile_record, 
      :complete => false,
      :token => Login.generate_token,
      :redirect_uri => params[:redirect_uri]

    session[:redirect_uri] = params[:redirect_uri]
    session[:attempted_token] = login[:token]
    session[:attempted_profile] = profile
    puts "Attempting authentication for #{session[:attempted_username]} via #{provider['code']}"

    if params[:openid_url]
      redirect "/auth/#{provider.code}?openid_url=#{session[:me]}" # TODO: verify this works
    else
      redirect "/auth/#{provider.code}"
    end
  end

  %w(get post).each do |method|
  send(method, '/auth/:name/callback') do
    auth = request.env['omniauth.auth']

    profile = Profile.first :user_id => session[:attempted_userid], :href => session[:attempted_profile]
    if profile.provider[:code] == 'open_id'
      attempted_url = session[:attempted_profile]
      actual_url = params['openid_url']
    elsif profile.provider[:code] == 'google_oauth2'
      attempted_url = session[:attempted_profile]
      actual_url = auth['extra']['raw_info']['link']
    else
      attempted_url = session[:attempted_profile]
      actual_url = profile.provider[:profile_url_template].gsub('{username}', auth['info']['nickname'])
    end

    puts "Auth complete!"
    puts "Provider: #{auth['provider']}"
    puts "UID: #{auth['uid']}"
    puts "URL: #{actual_url}"
    puts "Auth info:"
    puts auth.inspect
    puts "Session:"
    puts session

    if !actual_url || !attempted_url || attempted_url.downcase != actual_url.downcase  # case in-sensitive compare
      @message = "You just authenticated as '#{actual_url}' but your website linked to '#{attempted_url}'"
      title "Error"
      erb :error
    else
      token = session[:attempted_token]
      login = Login.first :token => token

      redirect_uri = session[:redirect_uri]

      session.clear

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