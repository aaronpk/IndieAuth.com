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

  def auth_path
    "/auth/start?me=#{URI.encode_www_form_component user.href}&provider=#{provider}&profile=#{URI.encode_www_form_component href}"
  end

  def sms_number
    if provider == 'sms'
      href.gsub /sms:\/?\/?/, ''
    end
  end
end
