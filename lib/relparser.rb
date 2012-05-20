class RelParser

  def initialize(opts={})
    @agent = Mechanize.new {|agent|
      agent.user_agent_alias = "Mac Safari"
    }
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
      @page = @agent.get @url
    end
    @page.links.each do |link|
      links << link.href if link.rel?("me")
    end
    links
  end

  def rel_me_links
    self.get "me"
  end

  def get_supported_links
    supported = []
    self.rel_me_links.each do |link|
      parser = RelParser.new link
      if parser.is_supported_provider?
        supported << link
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
      else
        # Check if the URL is an OpenID endpoint
        
      end
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
    puts link
    puts links_to
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
