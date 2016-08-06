class Provider

  def self.sms_regex
    /sms:\/?\/?([0-9\-+]+)/
  end

  def self.number_from_sms_uri(uri)
    uri.gsub /sms:\/?\/?/, ''
  end

  def self.email_regex
    /mailto:\/?\/?(.+@.+\..+)/
  end

  def self.email_from_mailto_uri(uri)
    uri.gsub /mailto:\/?\/?/, ''
  end

  def self.provider_for_url(url)
    if url.match Provider.sms_regex
      return 'sms'
    end

    if url.match Provider.email_regex
      return 'email'
    end

    Provider.regexes.each do |code,regex|
      if regex != '' && url.match(Regexp.new(regex))
        return code
      end
    end

    nil
  end

  def self.regexes
    {
      'beeminder' => 'https?:\/\/(?:www\.)?beeminder\.com\/(.+)',
      'eventbrite' => 'https?:\/\/(.+)\.eventbrite\.com',
      'flickr' => 'https?:\/\/(?:www\.)?flickr\.com\/(?:people\/)?([^\/]+)',
      'github' => 'https?:\/\/(?:www\.)?github\.com\/([^\/]+)',
      'google_oauth2' => 'https?:\/\/(?:www\.)?(?:profiles\.|plus\.|)google\.com\/([^\/]+)',
      'lastfm' => 'https?:\/\/(?:www\.)?last\.fm\/user\/(.+)',
      'twitter' => 'https?:\/\/(?:www\.)?twitter\.com\/([^\/]+)',
    }
  end

  def self.auth_path(provider, profile, me)
    path = "/auth/start?me=#{URI.encode_www_form_component me}&provider=#{provider}&profile=#{URI.encode_www_form_component profile}"
    if provider == 'twitter'
      match = profile.match Regexp.new(self.regexes['twitter'])
      twitter_username = match[1]
      path = "#{path}&screen_name=#{twitter_username}"
    end
    path
  end

end
