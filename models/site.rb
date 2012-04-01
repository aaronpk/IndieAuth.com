class Site
  include DataMapper::Resource
  property :id, Serial

  property :domain, String, :length => 255

  property :created_at, DateTime
  property :updated_at, DateTime

  def href
    "http://#{self.domain}/"
  end
end
