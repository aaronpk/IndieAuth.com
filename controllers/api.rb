class Controller < Sinatra::Base

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

  get '/verify' do
    code = params[:code] || params[:token]

    if code.nil?
      json_error 400, {error: "invalid_request", error_description: "Missing 'code' parameter"}
    end

    login = Login.first :token => code
    if login.nil?
      json_error 404, {error: "invalid_code", error_description: "The code provided was not found"}
    end

    if login.used_count > 0
      json_error 400, {error: "expired_code", error_description: "The code provided has already been used"}
    end

    login.last_used_at = Time.now
    login.used_count = login.used_count + 1
    login.save

    json_response 200, {:me => login.user['href']}
  end

end