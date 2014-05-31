class Controller < Sinatra::Base

  before do
    @server ||= OpenID::Server::Server.new(
        OpenID::Store::Memcache.new(Dalli::Client.new),
        "#{SiteConfig.root}/openid")
  end

  def render_openid_response(oidresp)
    @server.signatory.sign(oidresp) if oidresp.needs_signing
    web_response = @server.encode_response(oidresp)

    puts "Web response:"
    puts web_response.inspect

    case web_response.code
    when 200
      web_response.body
    when 302
      location = web_response.headers['location']
      puts "redirecting to: #{location} ..."
      redirect location
    else
      halt(500, web_response.body)
    end
  end

  get_or_post '/openid' do
    if params.empty?
      @message = "Invalid request"
      title "OpenID Error"
      return erb :error
    end

    params['openid.session_type'] = 'no-encryption' if params['openid.session_type'] == ''

    begin
      oidreq = @server.decode_request(params)
    rescue OpenID::Server::ProtocolError => e
      puts params.inspect
      puts "OpenID Error: #{e.to_s}"
      halt(200, "error: #{e.to_s}")
    rescue Exception => e
      puts params.inspect
      puts "OpenID Error: #{e.to_s}"
      halt(200, "error: #{e.to_s}")
    end

    if oidreq.kind_of? OpenID::Server::CheckIDRequest
      # Save all the openid.* parameters in a session, and redirect to /auth
      puts "Saving openid params in session"
      puts "Length: #{params.to_json.length}"
      session[:openid_params] = params.to_json

      redirect "/auth?me=#{params['openid.identity']}&redirect_uri=#{URI.encode_www_form_component('/openid/complete')}"
    else
      oidresp = @server.handle_request oidreq
      puts "oidresp"
      puts oidresp.inspect
      render_openid_response oidresp
    end
  end

  get '/openid/complete' do
    # Verify the indieauth token from params
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

    # Successfully authenticated as @domain

    if session[:openid_params].nil?
      @message = "Missing OpenID session data"
      title "OpenID Error"
      return erb :error
    end

    openid_params = JSON.parse(session[:openid_params])
    puts 'Saved openid params'
    jj openid_params


    puts "Cool, you authed via indieauth as #{@domain}"
    puts "Your openid session is trying to authenticate #{openid_params['openid.identity']}"

    # Make sure they match!
    a = URI.parse @domain
    b = URI.parse openid_params['openid.identity']

    a.path = '/' if a.path == ''
    b.path = '/' if b.path == ''

    valid = a.host == b.host and a.path == b.path

    if valid
      openid_params = JSON.parse(session[:openid_params])

      oidreq = @server.decode_request(openid_params)
      puts "OpenID Request:"
      puts oidreq.inspect

      oidresp = oidreq.answer(true, nil, openid_params['openid.identity'])

      render_openid_response oidresp
    else
      @message = "You authenticated as #{@domain} but were trying to claim #{openid_params['openid.identity']}"
      title "OpenID Error"
      return erb :error
    end
  end

end