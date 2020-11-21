module OmniAuth
  def self.provider_supported?(provider_name)
    case provider_name
    when nil
      exists = false
    when 'beeminder'
      exists = class_exists?('Beeminder')
    when 'eventbrite'
      exists = class_exists?('Eventbrite')
    when 'facebook'
      exists = class_exists?('Facebook')
    when 'flickr'
      exists = class_exists?('Flickr')
    when 'foursquare'
      exists = class_exists?('Foursquare')
    when 'github'
      exists = class_exists?('GitHub')
    when 'gitlab'
      exists = class_exists?('GitLab')
    when 'google_oauth2'
      exists = class_exists?('GoogleOauth2')
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
