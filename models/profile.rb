class Profile
  include DataMapper::Resource
  property :id, Serial

  belongs_to :user
  belongs_to :provider

  property :href, String, :length => 255
  property :verified, Boolean, :default => false

  property :active, Boolean, :default => true

  property :created_at, DateTime
  property :updated_at, DateTime

  def sms_number
    if provider.code == 'sms'
      href.gsub /sms:\/?\/?/, ''
    end
  end
end
