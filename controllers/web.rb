class Controller < Sinatra::Base

  get '/?' do
    title "IndieAuth - Sign in with your domain name"
    erb :index
  end

  get '/setup/?' do
    title "IndieAuth Documentation - Sign in with your domain name"
    erb :setup_instructions
  end

  get '/history/?' do
    title "The History of IndieAuth"
    erb :history
  end

  get '/faq/?' do
    title "IndieAuth FAQ"
    erb :faq
  end

  get '/developers/?' do
    title "IndieAuth for Developers"
    erb :developers
  end

  get '/sign-in/?' do
    title "IndieAuth Sign-In"
    erb :sign_in
  end

  get '/gpg/?' do
    title "Sign In with a GPG Key"
    erb :gpg
  end

end