class Controller < Sinatra::Base
  helpers do

    def title(value=nil)
      return @_title if value.nil?
      @_title = value
    end

    def viewport
      '<meta name="viewport" content="width=device-width,initial-scale=1">' if @_mobile
    end

    def partial(page, options={})
      erb page, options.merge!(:layout => false)
    end

    # The replacement for the user-facing side of this service, when one is
    # configured. Until config.yml names it, nothing is advertised.
    def replacement_service
      r = SiteConfig.replacement
      r if r && r.url && r.name
    end

    # Whether this request can only have come from a site that names
    # IndieAuth.com as its own authorization server.
    #
    # A scope beyond profile means the app wants an access token for the
    # user's website, and only the site's own authorization server can issue
    # one — so the site must declare this service. Without such a scope the
    # request may instead be an app using IndieAuth.com to sign a visitor in,
    # whose site need not mention this service at all.
    def indieauth_server_user?(scope)
      return false if scope.nil?
      (scope.to_s.split(/\s+/) - ['', 'profile', 'email']).any?
    end

    def display_url(url)
      return '' if url.nil?
      url.to_s.gsub(/https?:\/\//, '').gsub(/\/$/, '')
    end

    def add_params_to_url(urlstring, params)
      url = URI.parse urlstring
      query = URI.encode_www_form URI.decode_www_form(url.query || '').concat(params.to_a)
      url.query = query
      url.to_s
    end

    def path_class
      classes = request.path.split('/')
      classes.push('home') if request.path == '/'

      #if logged_in?
      #  classes.push('logged-in')
      #else
      #  classes.push('logged-out')
      #end

      classes.join(" ")
    end

  end
end
