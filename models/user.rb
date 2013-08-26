class User
  include DataMapper::Resource
  property :id, Serial

  property :href, String, :length => 255
  property :me_links, Text
  property :totp_secret, String, :length => 100

  has n, :logins
  has n, :profiles

  property :last_refresh_at, DateTime
  property :created_at, DateTime
  property :updated_at, DateTime

  def last_refresh
    timestamp = last_refresh_at || profiles.collect{|p| p.updated_at}.max
    if timestamp.nil?
      ""
    else
      diff = DateTime.now - timestamp
      if diff > 1
        # More than one day ago
        timestamp.strftime '%b %-d'
      elsif diff > (1.0 / 24.0)
        # More than 1 hour ago (less than one day)
        hours = (diff * 24).floor
        "#{hours} hour#{hours == 1 ? '' : 's'} ago"
      elsif diff > ((1.0 / 60.0) / 24.0)
        # More than 1 minute ago (less than one hour)
        minutes = (diff * 24 * 60).floor
        "#{minutes} min#{minutes == 1 ? '' : 's'} ago"
      else
        # Less than 1 minute ago
        seconds = (diff * 24 * 60 * 60).floor
        "#{seconds} sec#{seconds == 1 ? '' : 's'} ago"
      end
    end
  end
end
