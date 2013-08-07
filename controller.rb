class Controller < Sinatra::Base

  before do 
    if ["/session","/verify","/code"].include? request.path # don't set sessions for JSON api requests
      session[:null] = true   # weird hack to make the session object populate???
    end
    @site = Site.first_or_create :domain => request.host
  end

end
