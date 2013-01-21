class Provider
  include DataMapper::Resource
  property :id, Serial

  property :code, String, :length => 20
  property :client_id, String, :length => 255
  property :client_secret, String, :length => 255
  property :regex_username, String, :length => 255
  property :profile_url_template, String, :length => 255

  property :created_at, DateTime
  property :updated_at, DateTime

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
