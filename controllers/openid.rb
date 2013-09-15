class Controller < Sinatra::Base

  get '/openid/?' do
    title "IndieAuth - OpenID Provider"

    puts params.inspect

    # Save all the openid.* parameters in a session, and redirect to /auth
    session[:openid_params] = params.to_json

    redirect "/auth?me=#{params['openid.identity']}&redirect_uri=#{URI.encode_www_form_component('/openid/complete')}"
  end

  get '/openid/complete' do
    jj params
    jj JSON.parse(session[:openid_params])

    "Hello"
  end

end