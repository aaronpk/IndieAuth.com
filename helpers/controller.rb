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

    # The day everyone still using this service is moved over to the
    # replacement, while it is still ahead. Once it has passed the notice
    # stops counting down to it, rather than announcing something that has
    # already happened.
    def migration_date
      r = replacement_service
      return nil unless r && r.migrate_on
      date = Date.parse(r.migrate_on.to_s)
      date if date >= Date.today
    rescue ArgumentError
      nil
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

    # Whether this service still accepts websites, and apps, it has not seen
    # before. Both default to open: closing them changes what a live service
    # does, so it is a deliberate switch rather than a side effect of
    # deploying.
    def closed_to_new_sites?
      SiteConfig.closed_to_new_sites ? true : false
    end

    def closed_to_new_apps?
      SiteConfig.closed_to_new_apps ? true : false
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
