class User
  include DataMapper::Resource
  property :id, Serial

  property :href, String, :length => 255
  property :me_links, Text

  has n, :logins
  has n, :profiles

  property :created_at, DateTime
  property :updated_at, DateTime
end
