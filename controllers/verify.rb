class Controller < Sinatra::Base

  def json_error(code, data)
    json_response code, data
  end

  def json_response(code, data)
    halt code, {
      'Content-Type' => 'application/json;charset=UTF-8',
      'Cache-Control' => 'no-store',
      'Access-Control-Allow-Origin' => '*'
    },
    data.to_json
  end

  def form_encoded_response(code, data)
    halt code, {
      'Content-Type' => 'application/x-www-form-urlencoded',
      'Cache-Control' => 'no-store'
    },
    URI.encode_www_form(data)
  end

  def http_error(code, data)
    http_response code, data
  end

  def http_response(code, data)
    accept = env['rack-accept.request']
    if accept.media_type? 'application/x-www-form-urlencoded'
      # First check for form-encoded accept, which matches `Accept: */*` first
      form_encoded_response code, data
    elsif accept.media_type? 'application/json'
      # If they explicitly request application/json then return json
      json_response code, data
    else
      # Otherwise fall back to form-encoded
      form_encoded_response code, data
    end
  end

  get '/session' do
    if params[:token].nil?
      json_error 400, {error: "invalid_request", error_description: "Missing 'token' parameter"}
    end

    login = Login.decode_auth_code params[:token]
    if login.nil?
      json_error 404, {error: "invalid_token", error_description: "The token provided was not found"}
    end

    Log.save login

    json_response 200, {:me => login['me']}
  end

  get '/verify' do
    code = params[:code] || params[:token]

    if code.nil?
      json_error 400, {error: "invalid_request", error_description: "Missing 'code' parameter"}
    end

    login = Login.decode_auth_code code
    if login.nil?
      json_error 404, {error: "invalid_code", error_description: "The code provided was not found"}
    end

    if Login.expired? login
      json_error 400, {error: "expired_code", error_description: "The code provided has expired (valid for 60 seconds)"}
    end

    Log.save login

    json_response 200, {:me => login['me']}
  end

  options '/auth' do
    response.headers["Allow"] = "GET,POST,OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Cache-Control, Accept"
    200
  end

  # This is the POST route that handles verifying auth codes. It needs to match the name of the authorization URL
  # otherwise we would need a link-rel tag to specify the location of this endpoint somewhere.
  # This is for the "out of scope of OAuth 2.0" bit where the resource server verifies the code with the authorization server.
  post '/auth' do
    code = params[:code]

    puts "POST /auth\n#{params.inspect}"

    if code.nil?
      puts "Missing code parameter"
      http_error 400, {error: "invalid_request", error_description: "Missing 'code' parameter"}
    end

    login = Login.decode_auth_code code
    if login.nil?
      puts "Invalid code provided"
      http_error 404, {error: "invalid_request", error_description: "Invalid code provided"}
    end

    if Login.expired? login
      puts "The auth code expired"
      http_error 400, {error: "invalid_request", error_description: "The auth code has expired (valid for 60 seconds)"}
    end

    if login['redirect_uri'] != params[:redirect_uri]
      puts "The redirect_uri parameter did not match"
      http_error 400, {error: "invalid_request", error_description: "The 'redirect_uri' parameter did not match"}
    end

    Log.save login
    
    puts "Successful auth code verification"

    http_response 200, {
      :me => login['me'],
      :scope => login['scope']
    }
  end

end
