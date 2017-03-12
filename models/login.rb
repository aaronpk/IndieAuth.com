class Login

  def self.generate_auth_code(params)
    jwt = JWT.encode(params.merge({
      :nonce => Random.rand(100000..999999),
      :created_at => Time.now.to_i
    }), SiteConfig.jwt_key)

    salt = Time.now.to_i.to_s
    iv = OpenSSL::Cipher::Cipher.new('aes-256-cbc').random_iv
    encrypted = Encryptor.encrypt(jwt, :key => SiteConfig.jwt_key, :iv => iv, :salt => salt)
    iv64 = Base64.urlsafe_encode64 iv
    encrypted64 = Base64.urlsafe_encode64 encrypted

    "#{salt}.#{encrypted64}.#{iv64}"
  end

  def self.build_redirect_uri(params, response_type='code')
    auth_code = self.generate_auth_code params

    puts "Building redirect for login #{params.inspect}"
    if params[:redirect_uri]
      redirect_uri = URI.parse params[:redirect_uri]
      p = Rack::Utils.parse_query redirect_uri.query
      p[response_type] = auth_code
      p['me'] = params[:me]
      p['state'] = params[:state] if params[:state]
      redirect_uri.query = Rack::Utils.build_query p
      redirect_uri = redirect_uri.to_s 
    else
      redirect_uri = "/success?#{response_type}=#{auth_code}&me=#{URI.encode_www_form_component(params[:me])}"
      redirect_uri = "#{redirect_uri}&state=#{params[:state]}" if params[:state]
    end
    
    redirect_uri
  end

  def self.decode_auth_code(code)
    begin
      salt, encrypted64, iv64 = code.split '.'

      encrypted = Base64.urlsafe_decode64 encrypted64
      iv = Base64.urlsafe_decode64 iv64

      decrypted_code = Encryptor.decrypt(encrypted, :key => SiteConfig.jwt_key, :iv => iv, :salt => salt)

      login = JWT.decode(decrypted_code, SiteConfig.jwt_key)
      login = login.first # new JWT library returns a 2-element array after decoding
    rescue => e
      nil
    end
  end

  def self.expired?(login)
    return false
    # Auth codes are only valid for 60 seconds
    return login['created_at'] < Time.now.to_i - 60
  end

  def self.generate_token
    SecureRandom.urlsafe_base64(36)
  end

  def self.generate_verification_code
    Random.rand(1000..9999)
  end
end
