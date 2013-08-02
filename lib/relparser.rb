class RelParser

  def self.sms_regex
    /sms:\/?\/?([0-9\-+]+)/
  end

  def self.email_regex
    /mailto:\/?\/?(.+@.+\..+)/
  end

  attr_accessor :url

  def initialize(opts={})
    @agent = Mechanize.new {|agent|
      agent.user_agent_alias = "Mac Safari"
    }
    @agent.agent.http.ca_file = './lib/ca-bundle.crt'
    @url = opts
    @page = nil
    begin
      @meURI = URI.parse @url
    rescue => e
      # Could not parse URI
      return nil
    end
  
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

  def load_page
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
  end

  # Check whether an HTML page actually contains a link to the given profile
  def links_to(profile)
    load_page

    @page.links.each do |link|
      if link.rel? "me"
        puts link.href
        return true if link.href == profile
      end
    end

    return false
  end

  def rel_me_links(opts={})
    opts[:follow_redirects] = true if opts[:follow_redirects] == nil

    links = []
    load_page

    @page.links.each do |link|
      if link.rel? "me"
        # puts " --> #{link.href.inspect}"

        if link.href.match RelParser.sms_regex or link.href.match RelParser.email_regex
          links << link.href
        else
          begin
            original = URI.parse link.href

            if opts[:follow_redirects]

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

            else
              links << link.href
            end

          rescue => e
            # Ignore exceptions on invalid urls
            puts "Error parsing #{link.href}"
          end
        end
      end
    end

    links.uniq
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

    if @url.match RelParser.sms_regex
      return Provider.first :code => 'sms'
    end

    if @url.match RelParser.email_regex
      return Provider.first :code => 'email'
    end

    Provider.all.each do |provider|
      if provider['regex_username'] != '' && @url.match(Regexp.new provider['regex_username'])
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
      links_to = site_parser.rel_me_links :follow_redirects => false
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

      # Follow redirects and stop when a match is found
      stop = false
      while stop == false
        # Normalize
        siteURI.scheme = "http" if siteURI.scheme == "https"
        siteURI.path = "/" if siteURI.path == ""

        # Check if the URL matches
        if siteURI.scheme == @meURI.scheme && 
          siteURI.host == @meURI.host &&
          siteURI.path == @meURI.path
          links_back = true
          stop = true
          puts "Found match at: #{siteURI.to_s}"
        else
          # Check if siteURI is a redirect to something else, and continue
          unshortened = Unshorten.unshorten site_link, {:short_hosts => false, :use_cache => true, :max_level => 1}
          if unshortened == siteURI.to_s
            stop = true
            puts "Redirected to: #{unshortened} and stopping"
          else
            siteURI = URI.parse unshortened
            puts "Redirected to: #{unshortened}"
          end
          links_back = (unshortened == @meURI.to_s)
        end
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
