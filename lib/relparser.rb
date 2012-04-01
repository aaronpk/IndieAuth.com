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
      if provider_supported_by_url? link
        supported << link
      end
    end
    supported
  end

  def provider_supported_by_url?(url)
    provider = Provider.provider_for_url url
    return false if provider.nil?
    return OmniAuth.provider_supported? provider['code']
  end

  def verify_link(link)
    # Scan the external site for rel="me" links
    site_parser = RelParser.new link
    links_to = site_parser.get "me"
    
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
