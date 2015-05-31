class Provider

  def self.sms_regex
    /sms:\/?\/?([0-9\-+]+)/
  end

  def self.email_regex
    /mailto:\/?\/?(.+@.+\..+)/
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
      'geoloqi' => 'https?:\/\/(?:www\.)?geoloqi\.com\/([^\/]+)',
      'github' => 'https?:\/\/(?:www\.)?github\.com\/([^\/]+)',
      'google_oauth2' => 'https?:\/\/(?:www\.)?(?:profiles\.|plus\.|)google\.com\/([^\/]+)',
      'lastfm' => 'https?:\/\/(?:www\.)?last\.fm\/user\/(.+)',
      'twitter' => 'https?:\/\/(?:www\.)?twitter\.com\/([^\/]+)',
    }
  end

  def regex_username
    return_regex = nil
    Provider.regexes.each do |c,regex|
      if self.code == c
        return_regex = regex
      end
    end
    return_regex
  end

end
