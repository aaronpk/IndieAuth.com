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

  attr_accessor :url
  attr_accessor :redirects

  def initialize(opts={})
    @agent = Mechanize.new {|agent|
      agent.user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36"
      # Send an Accept header requesting HTML
      agent.request_headers = {
        'Accept' => 'text/html'
      }
      # Default to text/html if content-type is not set
      agent.post_connect_hooks << lambda { |_,_,response,_|
        if response.content_type.nil? || response.content_type.empty?
          response.content_type = 'text/html'
        end
      }
    }
    @agent.keep_alive = false
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
      if rels.include?('me') || rels.include?('authorization_endpoint') || rels.include?('pgpkey')
        return true if link.attribute("href").value == profile
        # Allow the site to link to it with a protocol relative link
        begin
          hrefURI = Addressable::URI.parse link.attribute("href").value
          hrefURI.scheme = 'https'
          profileURI = Addressable::URI.parse profile
          profileURI.scheme = 'https'
          return true if hrefURI.normalize.to_s == profileURI.normalize.to_s
        rescue
        end
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
      if rels.include? 'me' and link.attribute("href")
        # Resolve the URL relative to the base
        href = Addressable::URI.join(@url, link.attribute("href").value).to_s
        puts " --> #{link.attribute("href").value} (#{href}) rel=#{link.attribute("rel")}"

        if href.match Provider.email_regex
          # remove query string
          links << href.match(/(mailto:\/?\/?[^?]+@[^?]+\.[^?]+)/)[1]
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

    @page.search("[rel~=authorization_endpoint]").each do |link|
      puts " --> IndieAuth: #{link.attribute("href").value} rel=#{link.attribute("rel")}"
      href = link.attribute("href").value
      begin
        original = URI.parse href
        if original.host != SiteConfig.this_server
          endpoints << href
        end
      rescue => e
        puts "Error parsing #{href}"
      end
    end

    endpoints
  end

  def gpg_keys
    keys = []

    load_page

    return endpoints if @page.nil?

    @page.search("[rel~=pgpkey]").each do |link|
      href = link.attribute("href").value
      absolute = Addressable::URI.join(@url, href)
      puts " --> GPG Key: #{absolute} rel=#{link.attribute("rel")}"
      # Fetch the key. Assume the href links to a plaintext key
      begin
        response = @agent.get absolute
        keys << {
          :href => absolute,
          :key => response.body
        }
      rescue => e
        # just ignore errors
        puts "Error retrieving key at #{absolute}"
      end
    end

    keys
  end

  def is_supported_provider?
    provider = Provider.provider_for_url @url
    return false if provider.nil?
    return OmniAuth.provider_supported? provider
  end

  def verify_link(link, site_parser=nil)
    # Scan the external site for rel="me" links
    site_parser = RelParser.new link if site_parser.nil?

    begin
      links_to = site_parser.rel_me_links
    rescue SocketError
      return false, "Error trying to connect to #{link}"
    rescue InsecureRedirectError => e
      puts "verify_link: insecure redirect"
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
              # Allow http -> https redirects but prevent https -> http
              # Allow https://t.co to redirect insecurely to http sites since all t.co links are https now.
              # https://github.com/aaronpk/IndieAuth.com/issues/107
              if siteURI.host == "t.co"
                puts "Insecure t.co redirect: #{siteURI} -> #{unshortened}"
                siteURI = unshortened
                previous << unshortened
              else
                stop = true
                puts "Stopping because an insecure redirect was found :: #{siteURI} -> #{unshortened}"
                # If this link is otherwise a match, surface the redirect error
                a = unshortened.clone
                b = @meURI.clone
                a.scheme = "http"
                b.scheme = "http"
                if a == b
                  insecure_redirect_present = "Insecure redirect error. To fix this, link to #{insecure_redirect_present} directly."
                else
                  insecure_redirect_present = "Insecure redirect error. #{siteURI} redirected to #{unshortened}"
                end
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
      error_description = insecure_redirect_present
    else
      error_description = "No rel=me link was found on #{link} to #{@meURI}"
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
        redirect = Addressable::URI.join uri.to_s, response.headers['location']
        return redirect.normalize
      rescue URI::InvalidURIError => e
        return nil
      end
    else
      return nil
    end
  end

end
