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

  def find_all_relme_links(me_parser)
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

    if profile.match RelParser.sms_regex
      provider = Provider.first :code => 'sms'
    elsif profile.match RelParser.email_regex
      provider = Provider.first :code => 'email'
    else
      # Search the "profile" page for a rel=me link back to "me"
      profile_parser = RelParser.new profile

      provider = profile_parser.get_provider
    end

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
    else
      verified = me_parser.verify_link profile, profile_parser
    end

    if verified
      profile_record.verified = true
      profile_record.save
    end

    return provider, profile_record, verified
  end

  def auth_param_setup
    # Double check they provided valid parameters for "me" and "profile"

    me = verify_me_param
    profile = verify_profile_param

    user = save_user_record me

    me_parser = RelParser.new me

    links = find_all_relme_links me_parser

    if !links.include?(profile)
      json_error 400, {error: 'invalid_input', error_description: 'parameter "profile" must be one of the rel=me links in the site specified in the "me" parameter'}
    end

    provider, profile_record, verified = verify_user_profile me_parser, profile, user
    return me, profile, user, provider, profile_record, verified
  end

  # 1. Begin the auth process
  get '/auth' do
    title "IndieAuth - Sign in with your domain name"
    @me = params[:me]
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
    user.save

    json_response 200, {links: links}
  end

  # 3. Verify a link has a rel=me relation back to the specified site
  # Params:
  #  * me=example.com
  #  * profile=provider.com/user/xxxxx
  get '/auth/verify_link.json' do
    me, profile, user, provider, profile_record, verified = auth_param_setup

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
      auth_path: (verified ? auth_path : false)
    }
  end

  get '/auth/send_sms.json' do
    me, profile, user, provider, profile_record, verified = auth_param_setup

    if provider.nil? or provider.code != 'sms'
      json_error 400, {error: 'invalid_input', error_description: 'parameter "profile" must be SMS'}
    end

    login = Login.create :user => user,
      :provider => provider,
      :profile => profile_record, 
      :complete => false,
      :token => Login.generate_token,
      :redirect_uri => params[:redirect_uri],
      :sms_code => Login.generate_sms_code

    # Send the SMS now!
    @twilio = Twilio::REST::Client.new SiteConfig.twilio.sid, SiteConfig.twilio.token
    @twilio.account.sms.messages.create(
      :from => SiteConfig.twilio.number,
      :to => profile_record.sms_number,
      :body => "Your IndieAuth verification code is: #{login.sms_code}"
    )

    json_response 200, {
      me: me, 
      profile: profile, 
      provider: provider.code,
      result: 'sent'
    }
  end

  get '/auth/verify_sms.json' do
    me, profile, user, provider, profile_record, verified = auth_param_setup

    if provider.nil? or provider.code != 'sms'
      json_error 400, {error: 'invalid_input', error_description: 'parameter "profile" must be SMS'}
    end

    login = Login.first :user => user,
      :provider => provider,
      :sms_code => params[:code],
      :complete => false

    # TODO: Check code creation date and disallow old stuff

    if login.nil?
      json_error 400, {error: 'invalid_code', error_description: 'The code could not be verified'}
    end

    login.complete = true
    login.save

    if login.redirect_uri
      redirect_uri = URI.parse login.redirect_uri
      params = Rack::Utils.parse_query redirect_uri.query
      params['token'] = login.token
      redirect_uri.query = Rack::Utils.build_query params
      redirect_uri = redirect_uri.to_s 
    else
      redirect_uri = "/success?token=#{login.token}"
    end

    json_response 200, {
      me: me,
      profile: profile,
      provider: provider.code,
      result: 'verified',
      redirect: redirect_uri
    }
  end

  post '/auth/verify_email.json' do
    data = RestClient.post 'https://verifier.login.persona.org/verify', {
      :audience => SiteConfig.root,
      :assertion => params[:assertion]
    }
    response = JSON.parse data
    if response and response['status'] == 'okay'

      me = params[:me].sub(/(\/)+$/,'')
      me = "http://#{me}" unless me.match /^https?:\/\//

      user = User.first :href => me
      profile = user.profiles.first :href => "mailto:#{response['email']}"
      if profile.nil?
        json_error 400, {
          status: 'mismatch',
          reason: 'logged in as a different user'
        }
      else

        login = Login.create :user => user,
          :provider => Provider.first(:code => 'email'),
          :profile => profile,
          :complete => true,
          :token => Login.generate_token,
          :redirect_uri => params[:redirect_uri]

        if login.redirect_uri
          redirect_uri = URI.parse login.redirect_uri
          p = Rack::Utils.parse_query redirect_uri.query
          p['token'] = login.token
          redirect_uri.query = Rack::Utils.build_query p
          redirect_uri = redirect_uri.to_s 
        else
          redirect_uri = "/success?token=#{login.token}"
        end

        json_response 200, {
          status: response['status'],
          email: response['email'],
          redirect: redirect_uri
        }
      end
    else
      json_error 400, {
        status: response['status'],
        reason: response['reason']
      }
    end
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

    provider, profile_record, verified = verify_user_profile me_parser, profile, user

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
        if redirect_uri
          redirect_uri = URI.parse redirect_uri
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
      json_error 400, {error: "invalid_request", error_description: "Missing 'token' parameter"}
    end

    login = Login.first :token => params[:token]
    if login.nil?
      json_error 404, {error: "invalid_token", error_description: "The token provided was not found"}
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
    halt code, {
        'Content-Type' => 'application/json;charset=UTF-8',
        'Cache-Control' => 'no-store'
      }, 
      data.to_json
  end

  def json_response(code, data)
    halt code, {
        'Content-Type' => 'application/json;charset=UTF-8',
        'Cache-Control' => 'no-store'
      }, 
      data.to_json
  end

end
