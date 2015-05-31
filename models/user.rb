class User
  def self.set_last_refresh(me, time)
    R.set "indieauth::refreshed::#{me}", time
  end

  def self.last_refresh(me)
    timestamp = R.get "indieauth::refreshed::#{me}"
    if timestamp.nil?
      ""
    else
      seconds = Time.now.to_i - timestamp.to_i
      date = Time.at timestamp.to_i
      if seconds > 86400
        # More than one day ago
        date.strftime '%b %-d'
      elsif seconds > (60 * 60)
        # More than 1 hour ago (less than one day)
        hours = (seconds / 60 / 60).floor
        "#{hours} hour#{hours == 1 ? '' : 's'} ago"
      elsif seconds > 60
        # More than 1 minute ago (less than one hour)
        minutes = (seconds / 60).floor
        "#{minutes} min#{minutes == 1 ? '' : 's'} ago"
      else
        # Less than 1 minute ago
        seconds = (seconds).floor
        "#{seconds} sec#{seconds == 1 ? '' : 's'} ago"
      end
    end
  end
end
