class RelParser

  class InsecureRedirectError < Exception
    attr_accessor :message
  end

  class SSLError < Exception
    attr_accessor :message
    attr_accessor :url
  end

  class InvalidContentError < Exception
    attr_accessor :message
    attr_accessor :url
  end

  def self.sms_regex
    /sms:\/?\/?([0-9\-+]+)/
  end

  def self.email_regex
    /mailto:\/?\/?(.+@.+\..+)/
  end

  attr_accessor :url
  attr_accessor :redirects

  def initialize(opts={})
    @agent = Mechanize.new {|agent|
      agent.user_agent_alias = "Mac Safari"
      # Default to text/html if content-type is not set
      agent.post_connect_hooks << lambda { |_,_,response,_|
        if response.content_type.nil? || response.content_type.empty?
          response.content_type = 'text/html'
        end
      }
    }
    @agent.agent.http.ca_file = './lib/ca-bundle.crt'
    @url = opts
    @page = nil
    @redirects = []
    begin
      @meURI = URI.parse @url
    rescue => e
      # Could not parse URI
      return nil
    end
  
    # Normalize
    #@meURI.scheme = "http" if @meURI.scheme == "https"
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
        # Follow redirects to the end checking for cross-protocol links (http->https)
        stop = false
        previous = [] # used to prevent redirect loops
        url = URI.parse @url
        secure = true
        while stop == false
          unshortened = RelParser.follow url
          if unshortened == nil
            stop = true
          elsif previous.include? unshortened
            stop = true
            puts "Stopping because we've already seen the URL :: #{unshortened} is in #{previous}"
          elsif url.scheme == "https" && unshortened.scheme == "http"
            stop = true
            secure = false
            puts "Stopping because an insecure redirect was found :: #{url} -> #{unshortened}"
            e = InsecureRedirectError.new
            e.message = "Insecure redirect error. #{url.scheme} redirected to #{unshortened.scheme}. To fix, link to #{unshortened} directly."
            raise e
          else
            puts "Redirect found: #{url} -> #{unshortened}"
            url = unshortened
            @redirects << unshortened.to_s # Keep track of all the redirects seen in case the external profile links to one in the chain
            previous << unshortened
          end
        end

        if secure == false
          return []
        end

        @page = @agent.get url.to_s
      rescue OpenSSL::SSL::SSLError => e
        puts "!!!! SSL ERROR: #{e.message}"
        er = SSLError.new
        er.url = url
        raise er
      rescue => e # catch all errors and return a blank list
        puts "!!!!! #{e}"
        puts e.class
        raise e
      end
      if @page.class != Mechanize::Page
        e = InvalidContentError.new
        e.message = "The URL #{url} returned an invalid content-type: '#{@page.response['content-type']}'"
        e.url = url
        raise e
        # Server didn't return content-type: html, so mechanize can't turn it into a Page class.
      end
    end
  end

  # Check whether an HTML page actually contains a link to the given profile
  def links_to(profile)
    load_page

    return false if @page.nil?

    @page.search("a,link").each do |link|
      rels = (link.attribute("rel").to_s || '').split(/ /)
      if rels.include?('me') || rels.include?('authorization_endpoint')
        return true if link.attribute("href").value == profile
      end
    end

    return false
  end

  def rel_me_links(opts={})
    links = []
    load_page

    return links if @page.nil?

    @page.search("a,link").each do |link|
      rels = (link.attribute("rel").to_s || '').split(/ /)
      if rels.include? 'me'
        puts " --> #{link.attribute("href").value} rel=#{link.attribute("rel")}"
        href = link.attribute("href").value

        if href.match RelParser.sms_regex or href.match RelParser.email_regex
          links << href
        else
          begin
            original = URI.parse href
            #puts "Path: #{original.path.inspect}"
            links << href
          rescue => e
            # Ignore exceptions on invalid urls
            puts "Error parsing #{href}"
          end
        end
      end
    end

    links.uniq
  end

  def auth_endpoints
    endpoints = []
    load_page

    return endpoints if @page.nil?

    @page.search("[rel=authorization_endpoint]").each do |link|
      puts " --> IndieAuth: #{link.attribute("href").value} rel=#{link.attribute("rel")}"
      endpoints << link.attribute("href").value
    end

    endpoints
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

    # TODO: Fix the below to re-enable OpenID
    #return Provider.first(:code => 'indieauth')
    return nil

    # Check if the URL is an OpenID endpoint
    # rel_me_links # fetch the page contents now which populates @page
    # # If the page contains an openID tag, use it!
    # return nil if @page.class != Mechanize::Page

    # if @page.at('/html/head/link[@rel="openid.server"]/@href') || @page.at('/html/head/link[@rel="openid2.provider"]/@href')
    #   return Provider.first(:code => 'open_id')
    # end
    # return nil
  end

  def is_supported_provider?
    provider = self.get_provider
    return false if provider.nil?
    return OmniAuth.provider_supported? provider['code']
  end

  def verify_auth_endpoint(link, site_parser=nil)
    site_parser = RelParser.new link if site_parser.nil?
    begin 
    rescue SocketError
      return false, "Error trying to connect to #{link}"
    rescue InsecureRedirectError => e
      return false, e.message
    end

    puts "==========="
    puts "Page: #{link}"

    # Check the HTTP headers to see if the endpoint returns "IndieAuth: authorization_endpoint"
    begin
      @page = @agent.head link
      puts "IndieAuth: #{@page.header['indieauth']}"
      if @page.header['indieauth'] == 'authorization_endpoint'
        return true, nil
      else
        return false, 'Endpoint is not an authorization endpoint'
      end
    rescue OpenSSL::SSL::SSLError => e
      puts "!!!! SSL ERROR: #{e.message}"
      er = SSLError.new
      er.url = link
      raise er
    rescue => e # catch all errors and return a blank list
      puts "!!!!! #{e}"
      puts e.class
      raise e
    end

    return false, 'unknown error'
  end

  def verify_link(link, site_parser=nil)
    # Scan the external site for rel="me" links
    site_parser = RelParser.new link if site_parser.nil?
    begin
      links_to = site_parser.rel_me_links
    rescue SocketError
      return false, "Error trying to connect to #{link}"
    rescue InsecureRedirectError => e
      return false, e.message
    end

    puts "==========="
    puts "Page: #{link}"
    puts "Links to: #{links_to}"
    puts "Looking for: #{@meURI} Redirects: #{@redirects}"
    puts
    
    # Find any that match the user's entered "me" link

    # First check if it's in the array so we can skip making HTTP requests to check for redirects
    look_for = @redirects.clone
    look_for << @meURI.to_s
    # puts "Looking for: #{look_for.inspect}"
    # puts "Links to: #{links_to.inspect}"
    # puts "Intersection: #{(links_to & look_for).inspect}"
    if (links_to & look_for).length > 0
      puts "Found it!"
      return true, nil
    end

    # Continue searching through links and follow redirects, and stop when a match is found
    insecure_redirect_present = false
    links_to.each do |site_link|
      siteURI = URI.parse site_link

      if siteURI.scheme and siteURI.host

        stop = false
        previous = [] # used to prevent redirect loops
        while stop == false
          # Normalize
          siteURI.path = "/" if siteURI.path == ""

          # Check if the URL matches
          if look_for.include? siteURI.to_s
            stop = true
            puts "Found match at: #{siteURI.to_s}"
            return true, nil

          else
            # Check if siteURI is a redirect
            unshortened = RelParser.follow siteURI
            if unshortened == nil
              stop = true
              puts "Stopping because no redirect was found: #{siteURI}"
              previous << unshortened
            elsif previous.include? unshortened
              stop = true
              puts "Stopping because we've already seen the URL :: #{unshortened} is in #{previous}"
            elsif siteURI.scheme == "https" && unshortened.scheme == "http"
              # Allow http -> https redirects
              stop = true
              puts "Stopping because an insecure redirect was found :: #{siteURI} -> #{unshortened}"
              # If this link is otherwise a match, surface the redirect error
              a = unshortened.clone
              b = @meURI.clone
              a.scheme = "http"
              b.scheme = "http"
              if a == b
                insecure_redirect_present = unshortened
              end
            else
              puts "Redirect found: #{siteURI} -> #{unshortened}"
              siteURI = unshortened
              previous << unshortened
            end

            if siteURI == @meURI
              stop = true
              return true, nil
            end
          end
        end # while
      else
        puts "No scheme/host found: #{siteURI}"

        # TODO: Fetch this page and look for a match there
        # https://github.com/aaronpk/IndieAuth/issues/1

      end # if scheme and host

    end # each links_to

    # Returns here only if no links were found on the site
    if insecure_redirect_present
      error_description = "Insecure redirect error. To fix this, link to #{insecure_redirect_present} directly."
    else
      error_description = nil
    end
    return false, error_description
  end

  # Follow the given URI (object) for a single redirect, and return nil if no redirect is returned
  def self.follow uri
    return nil if uri.nil?

    begin
      response = HTTParty.get uri.to_s, {:follow_redirects => false}
    rescue => e
      return nil
    end
    
    if response.headers['location']
      begin
        redirect = URI.parse response.headers['location']
        redirect.scheme = uri.scheme if redirect.scheme == nil 
        redirect.host = uri.host if redirect.host == nil
        redirect.path = '/' if redirect.path == ''
        return redirect
      rescue URI::InvalidURIError => e
        return nil
      end
    else
      return nil
    end
  end

end
