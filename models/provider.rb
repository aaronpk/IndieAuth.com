class Provider # < Hash
  #include Hashie::Extensions::MethodAccess
  include DataMapper::Resource
  property :id, Serial

  property :name, String, :length => 50
  property :home_page, String, :length => 100
  property :code, String, :length => 20
  property :client_id, String, :length => 255
  property :client_secret, String, :length => 255

  property :created_at, DateTime
  property :updated_at, DateTime

  def self.sms_regex
    /sms:\/?\/?([0-9\-+]+)/
  end

  def self.email_regex
    /mailto:\/?\/?(.+@.+\..+)/
  end

  def self.provider_for_url(url)
    if url.match Provider.sms_regex
      return Provider.first :code => 'sms'
    end

    if url.match Provider.email_regex
      return Provider.first :code => 'email'
    end

    Provider.regexes.each do |c,regex|
      if regex != '' && url.match(Regexp.new(regex))
        return Provider.first :code => c
      end
    end
  end

  def self.regexes
    {
      'beeminder' => 'https?:\/\/(?:www\.)?beeminder\.com\/(.+)',
      'eventbrite' => 'https?:\/\/(.+)\.eventbrite\.com',
      'flickr' => 'https?:\/\/(?:www\.)?flickr\.com\/(?:people\/)?([^\/]+)',
      'geoloqi' => 'https?:\/\/(?:www\.)?geoloqi\.com\/([^\/]+)',
      'github' => 'https?:\/\/(?:www\.)?github\.com\/([^\/]+)',
      'google_oauth2' => 'https?:\/\/(?:www\.)?(?:profiles\.|plus\.|)google\.com\/([^\/]+)',
      'lastfm' => 'https?:\/\/(?:www\.)?last\.fm\/user\/(.+)',
      'twitter' => 'https?:\/\/(?:www\.)?twitter\.com\/([^\/]+)'
    }
  end

  def regex_username
    return_regex = nil
    Provider.regexes.each do |c,regex|
      if self.code == c
        return_regex = regex
      end
    end
    return_regex
  end

  def username_for_url(url)
    #puts "username_for_url #{url}"
    parser = RelParser.new url
    provider = parser.get_provider
    return nil if provider.nil?
    return url if provider['code'] == 'open_id'
    url.match provider['regex_username']
    #puts "Username for #{url} is #{$1}"
    return $1
  end
end
