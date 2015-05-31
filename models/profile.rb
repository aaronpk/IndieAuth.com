class Profile
  include DataMapper::Resource
  property :id, Serial

  belongs_to :user

  property :href, String, :length => 255
  property :verified, Boolean, :default => false
  property :provider, String, :length => 100
  property :active, Boolean, :default => true

  property :created_at, DateTime
  property :updated_at, DateTime
end
