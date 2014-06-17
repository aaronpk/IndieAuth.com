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

  def auth_path
    "/auth/start?me=#{URI.encode_www_form_component user.href}&profile=#{URI.encode_www_form_component href}"
  end

  def sms_number
    if provider.code == 'sms'
      href.gsub /sms:\/?\/?/, ''
    end
  end
end
