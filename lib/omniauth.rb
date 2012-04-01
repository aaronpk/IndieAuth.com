module OmniAuth
  def self.provider_supported?(provider_name)
    case provider_name
    when nil
      exists = false
    when 'facebook'
      exists = class_exists?('Facebook')
    when 'flickr'
      exists = class_exists?('Flickr')
    when 'foursquare'
      exists = class_exists?('Foursquare')
    when 'geoloqi'
      exists = class_exists?('Geoloqi')
    when 'github'
      exists = class_exists?('GitHub')
    when 'google'
      exists = class_exists?('Google')
    when 'twitter'
      exists = class_exists?('Twitter')
    else
      exists = false
    end
    exists
  end

  def self.class_exists?(class_name)
    klass = OmniAuth::Strategies.const_get(class_name)
    return klass.is_a?(Module)
  rescue NameError
    return false
  end
end