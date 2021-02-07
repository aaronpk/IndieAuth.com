module OmniAuth
  def self.provider_supported?(provider_name)
    case provider_name
    when nil
      exists = false
    when 'github'
      exists = class_exists?('GitHub')
    when 'gitlab'
      exists = class_exists?('GitLab')
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
