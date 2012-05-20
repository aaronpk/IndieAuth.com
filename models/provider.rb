class Provider
  include DataMapper::Resource
  property :id, Serial

  property :code, String, :length => 20
  property :client_id, String, :length => 255
  property :client_secret, String, :length => 255
  property :regex_username, String, :length => 255

  property :created_at, DateTime
  property :updated_at, DateTime

  def username_for_url(url)
    #puts "username_for_url #{url}"
    provider = Provider.provider_for_url url
    return nil if provider.nil?
    url.match provider['regex_username']
    #puts "Username for #{url} is #{$1}"
    return $1
  end

  def self.provider_for_url(url)
    # puts "provider_for_url #{url}"
    return nil if url.nil?
    Provider.all.each do |provider|
      if provider['regex_username'] && url.match(Regexp.new provider['regex_username'])
        # puts "Provider name for #{url} is #{provider['code']}"
        return provider
      else
        # Check if the URL is an OpenID endpoint
      end
    end
    return nil
  end
end
