class Profile
  include DataMapper::Resource
  property :id, Serial

  belongs_to :user
  belongs_to :provider

  property :href, String, :length => 255
  property :verified, Boolean, :default => false

  property :created_at, DateTime
  property :updated_at, DateTime
end
