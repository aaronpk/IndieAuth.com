class Login
  include DataMapper::Resource
  property :id, Serial

  belongs_to :user
  belongs_to :profile
  belongs_to :provider

  property :token, String, :length => 128, :index => true
  property :redirect_uri, String, :length => 255
  property :complete, Boolean, :default => false
  property :used_count, Integer, :default => 0

  property :created_at, DateTime
  property :last_used_at, DateTime

  def self.generate_token
    SecureRandom.urlsafe_base64(36)
  end
end
