class Profile

  def self.find(opts)
    data = R.hget "indieauth::profile::#{opts[:me]}", opts[:profile]
    return JSON.parse data if data
    nil
  end

  def self.all(opts)
    data = R.hgetall "indieauth::profile::#{opts[:me]}"
  end

  def self.save(opts, data)
    R.hset "indieauth::profile::#{opts[:me]}", opts[:profile], data.to_json
    R.expire "indieauth::profile::#{opts[:me]}", 86400*30
  end

  def self.delete(opts)
    R.hdel "indieauth::profile::#{opts[:me]}", opts[:profile]
  end

end
