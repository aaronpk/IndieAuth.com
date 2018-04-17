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
