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
    @meURI.path = "/" if @meURI.path == ""  end
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
    links = self.get "me"
    @links = []
    links.each do |link|

      # Scan the external site for rel="me" links
      site_parser = RelParser.new link
      site_links = site_parser.get "me"
      
      puts "==========="
      puts link
      puts site_links
      puts
      
      links_back = false
      # Find any that match the user's entered "me" link

      site_links.each do |site_link|
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

      if links_back
        @links << {
          :url => link,
          :me_links => site_links
        }
      end
    end
    @links
  end

  def get_supported_links
    links = self.rel_me_links

    supported = []
    links.each do |link|
      if provider_supported_by_url? link[:url]
        supported << link[:url]
      end
    end

    supported
  end

  def provider_name_for_url(url)
    if url.match /https?:\/\/(?:www\.)?facebook\.com\/([^\/]+)/
      name = 'facebook'
    elsif url.match /https?:\/\/(?:www\.)?flickr\.com\/(?:photos\/)?([^\/]+)/
      name = 'flickr'
    elsif url.match /https?:\/\/(?:www\.)?geoloqi\.com\/([^\/]+)/
      name = 'geoloqi'
    elsif url.match /https?:\/\/(?:www\.)?github\.com\/([^\/]+)/
      name = 'github'
    elsif url.match /https?:\/\/(?:www\.)?profiles\.google\.com\/([^\/]+)/
      name = 'google'
    elsif url.match /https?:\/\/(?:www\.)?twitter\.com\/([^\/]+)/
      name = 'twitter'
    else
      name = nil
    end
    puts "Provider name for #{url} is #{name}"
    name
  end

  def username_for_url(url)
    if url.match /https?:\/\/(?:www\.)?facebook\.com\/([^\/]+)/
      name = $1
    elsif url.match /https?:\/\/(?:www\.)?flickr\.com\/(?:photos\/)?([^\/]+)/
      name = $1
    elsif url.match /https?:\/\/(?:www\.)?geoloqi\.com\/([^\/]+)/
      name = $1
    elsif url.match /https?:\/\/(?:www\.)?github\.com\/([^\/]+)/
      name = $1
    elsif url.match /https?:\/\/(?:www\.)?profiles\.google\.com\/([^\/]+)/
      name = $1
    elsif url.match /https?:\/\/(?:www\.)?twitter\.com\/([^\/]+)/
      name = $1
    else
      name = nil
    end
    puts "Username for #{url} is #{name}"
    name
  end

  def provider_supported_by_url?(url)
    name = provider_name_for_url url
    OmniAuth.provider_supported? name
  end

end
