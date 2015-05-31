class Log

  def self.save(login)
    # login is the payload decoded from Login.decode_auth_code
    R.rpush "indieauth::logs", login.to_json
  end

  def self.flush
    while entry = R.lindex("indieauth::logs", 0) do
      begin
        entry = JSON.parse entry
        # puts "Sending log entry: #{entry}"
        # puts "me=#{entry['me']}"
        response = HTTParty.post "#{SiteConfig.stats.server}/report", {
          :headers => { 'Authorization' => "Bearer #{SiteConfig.stats.token}" },
          :body => {
            :me => entry['me'],
            :provider => entry['provider'],
            :profile => entry['profile'],
            :scope => entry['scope'],
            :redirect_uri => entry['redirect_uri'],
            :client_id => entry['client_id']
          }
        }
        # jj response.parsed_response
        if response && response.code == 200 && response.parsed_response['result'] == 'ok'
          R.lpop "indieauth::logs"
        else
          puts "Something went wrong trying to flush the stats. Stop for now."
          raise Exception.new "StatsError"
        end
      rescue => e
        puts "Error saving entry! Stop for now."
        raise e
      end
    end
  end

end