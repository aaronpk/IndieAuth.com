class RelParser

  def initialize(opts={})
    @agent = Mechanize.new {|agent|
      agent.user_agent_alias = "Mac Safari"
    }
    @agent.agent.http.ca_file = './lib/ca-bundle.crt'
    @url = opts
    @page = nil
    @meURI = URI.parse @url
  
    # Normalize
    @meURI.scheme = "http" if @meURI.scheme == "https"
    @meURI.path = "/" if @meURI.path == ""  
  end

  def agent 
    @agent
  end

  def page
    @page
  end

  def get(tag)
    links = []
    if @page.nil?
      puts "<<<<<<< FETCHING #{@url} >>>>>>>"
      begin
        @page = @agent.get @url
      rescue => e # catch all errors and return a blank list
        puts e
        return []
      end
      if @page.class != Mechanize::Page
        # Server didn't return content-type: html, so mechanize can't turn it into a Page class.
        # Can't parse it, so return nil
        return []
      end
    end

    @page.links.each do |link|
      if link.rel?(tag)
        # puts " --> #{link.href.inspect}"

        begin
          original = URI.parse link.href

          # Follow redirects (un-shorten links) 
          # Mostly to follow twitter's profile links wrapped in t.co
          unshortened = Unshorten.unshorten link.href, {:short_hosts => false, :use_cache => true}

          # If the original link is http but the redirect is to an https link, use the original.
          # This is to avoid introducing a trust hole, since if someone is using https we are assuming they are using https everywhere.
          begin
            actual = URI.parse unshortened

            # If there is no host in the un-shortened version, assume it's the same host as the original link.
            # Some servers return an absolute path in the 301 redirect. For example:
            #
            # http://picasaweb.google.com/wnorris
            # Location: /111832530347449196055?gsessionid=6SZtIqXiPEW45p_gwXf2Xw
            if actual.host == nil
              actual.host = original.host
            end

            if original.scheme == actual.scheme
              puts " Found URL: #{actual}"
              links << actual.to_s
            else
              # TODO: Figure out how to surface this error to the user
              puts "     skipping redirect due to protocol mismatch"
            end
          rescue => e
            # Ignore exceptions parsing the URL
            puts "Error parsing #{unshortened}"
          end

        rescue => e
          # Ignore exceptions on invalid urls
          puts "Error parsing #{link.href}"
        end
      end
    end

    links.uniq
  end

  def rel_me_links
    self.get "me"
  end

  def get_supported_links
    supported = []
    self.rel_me_links.each do |link|
      parser = RelParser.new link
      if parser.is_supported_provider?
        supported << {
          :link => link,
          :parser => parser
        }
      end
    end
    supported
  end

  def get_provider
    return nil if @url.nil?
    Provider.all.each do |provider|
      if provider['regex_username'] && @url.match(Regexp.new provider['regex_username'])
        # puts "Provider name for #{url} is #{provider['code']}"
        return provider
      end
    end

    # TODO: Remove this to enable OpenID
    return nil

    # Check if the URL is an OpenID endpoint
    rel_me_links # fetch the page contents now which populates @page
    # If the page contains an openID tag, use it!
    return nil if @page.class != Mechanize::Page

    if @page.at('/html/head/link[@rel="openid.server"]/@href') || @page.at('/html/head/link[@rel="openid2.provider"]/@href')
      return Provider.first(:code => 'open_id')
    end
    return nil
  end

  def is_supported_provider?
    provider = self.get_provider
    return false if provider.nil?
    return OmniAuth.provider_supported? provider['code']
  end

  def verify_link(link, site_parser=nil)
    # Scan the external site for rel="me" links
    site_parser = RelParser.new link if site_parser.nil?
    begin
      links_to = site_parser.get "me"
    rescue SocketError
      return false
    end

    puts "==========="
    puts "Page: #{link}"
    puts "Links to: #{links_to}"
    puts
    
    links_back = false
    # Find any that match the user's entered "me" link

    links_to.each do |site_link|
      siteURI = URI.parse site_link
      # Normalize
      siteURI.scheme = "http" if siteURI.scheme == "https"
      siteURI.path = "/" if siteURI.path == ""

      # Compare
      if siteURI.scheme == @meURI.scheme && 
        siteURI.host == @meURI.host &&
        siteURI.path == @meURI.path
        links_back = true
      end
    end

    # if links_back
    #   @links << {
    #     :url => link,
    #     :me_links => links_to
    #   }
    # end
    links_back
  end

end
