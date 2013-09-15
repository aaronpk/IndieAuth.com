class Controller < Sinatra::Base

  get '/openid/?' do
    title "IndieAuth - OpenID Provider"
    erb :openid
  end

end