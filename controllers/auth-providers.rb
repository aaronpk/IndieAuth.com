class Controller < Sinatra::Base

  get '/auth/send_email.json' do
    me, profile, provider, verified, error_description = auth_param_setup

    if provider.nil? or provider != 'email'
      json_error 200, {error: 'invalid_input', error_description: 'parameter "profile" must be email'}
    end

    code = Login.generate_verification_code
    R.set "indieauth::email::#{me}", code, :ex => 300 # valid for 300 seconds
    R.set "indieauth::email::#{me}::session", {
      redirect_uri: session[:redirect_uri],
      state: session[:state],
      scope: session[:scope],
    }.to_json, :ex => 300

    email = Provider.email_from_mailto_uri(profile)

    # Send the email now!
    mailgun = Mailgun()
    mailgun.messages.send_email({
      to: email,
      from: SiteConfig.mailgun.from,
      subject: "Your IndieAuth.com verification code",
      text: "Your IndieAuth.com verification code is: #{code}"
    })

    json_response 200, {
      result: 'sent',
      verify: "https://#{SiteConfig.this_server}"
    }
  end

  get '/auth/verify_email.json' do
    me, profile, provider, verified, error_description = auth_param_setup

    if provider.nil? or provider != 'email'
      json_error 200, {error: 'invalid_input', error_description: 'parameter "profile" must be email'}
    end

    if params[:code] != R.get("indieauth::email::#{me}")
      json_error 200, {error: 'invalid_code', error_description: 'The code could not be verified'}
    end

    data = JSON.parse R.get("indieauth::email::#{me}::session")

    redirect_uri = Login.build_redirect_uri({
      :me => me,
      :provider => 'email',
      :profile => profile,
      :redirect_uri => data['redirect_uri'],
      :state => data['state'],
      :scope => data['scope']
    })

    json_response 200, {
      me: me,
      profile: profile,
      provider: provider,
      result: 'verified',
      redirect: redirect_uri
    }
  end

  get '/totp' do
    if params[:token].nil?
      title "TOTP login is no longer supported"
      return erb :totp_login
    end
  end

  post '/auth/start_gpg.json' do
    me, profile, provider, verified, error_description = auth_param_setup

    if provider.nil? or provider != 'gpg'
      json_error 200, {error: 'invalid_input', error_description: 'This profile must be a link to a GPG key'}
    end

    json_response 200, {
      plaintext: generate_gpg_challenge(me, profile, params),
      key_url: profile
    }
  end

  def generate_gpg_challenge(me, profile, params) 
    JWT.encode({
      :me => me,
      :profile => profile,
      :redirect_uri => URI.encode(params[:redirect_uri]),
      :state => params[:state],
      :scope => params[:scope],
      :nonce => Random.rand(100000..999999),
      :created_at => Time.now.to_i
    }, SiteConfig.jwt_key)
  end

  post '/auth/verify_gpg.json' do
    if !params[:signature]
      json_error 200, {error: 'missing_signature', error_description: "No signature was provided"}
    end

    if !params[:plaintext]
      json_error 200, {error: 'missing_data', error_description: "The request was missing some data"}
    end

    # Decode the request parameters. We can trust everything in "expected" because it was signed by the server.
    begin
      expected = JWT.decode(params[:plaintext], SiteConfig.jwt_key)
      expected = expected[0] # new JWT library returns a 2-element array after decoding
    rescue => e
      json_error 200, {error: 'request_error', error_description: "There was an error verifying this request."}
    end

    # Look up the key to make sure we know about it already
    puts "Expecting user #{expected['me']} to authenticate"

    begin
      agent = Mechanize.new {|agent|
        agent.user_agent_alias = "Mac Safari"
        agent.request_headers = {
          'Accept' => 'text/plain'
        }
        # Default to text/plain parsing if content-type is not set
        agent.post_connect_hooks << lambda { |_,_,response,_|
          if response.content_type.nil? || response.content_type.empty?
            response.content_type = 'text/plain'
          end
        }
      }
      agent.agent.http.ca_file = './lib/ca-bundle.crt'
      # Use the key indicated by the signed JWT payload
      absolute = URI.join expected['me'], expected['profile']
      response = agent.get absolute
      public_key = response.body
    rescue => e
      json_error 200, {error: 'error_fetching_key', error_description: "There was an error fetching the key from #{expected['profile']}"}
    end

    verified = false

    # Verify the signature

    # The plaintext version is actually a JWT-signed payload that has all the info about the request
    # (me, redirect_uri, scope, etc)
    begin
      crypto = GPGME::Crypto.new

      # Import their public key 
      result = GPGME::Key.import(public_key)

      # Get the Key object for the key that was just imported
      key = GPGME::Key.find(:public, result.imports[0].fpr).first

      # Find the fingerprint of the key that was just imported (or had been previously imported)
      fingerprint = key.fingerprint
      puts "Fingerprint of imported key: #{key.fingerprint}"
      puts "Subkeys:"
      puts key.subkeys

      signature = GPGME::Data.new(params[:signature])
      data = crypto.verify(signature) do |sig|
        puts sig.to_s
        verified = sig.valid?

        if !verified
          json_error 200, {error: 'invalid_signature', error_description: "The signature was invalid. Please try again."}
        end

        puts "Fingerprint of key that was used to sign: #{sig.fpr}"
        # Check the fingerprint of any subkeys
        valid = false
        if fingerprint == sig.fpr
          puts "Matched the master key fingerprint"
          valid = true
        end
        key.subkeys.each do |subkey|
          if subkey.fingerprint == sig.fpr
            puts "Matched subkey #{subkey.fingerprint}"
            valid = true
          end
        end

        if !valid
          json_error 200, {error: 'key_mismatch', error_description: "The key used to sign the challenge was not the key at #{absolute}."}
        end

      end
    rescue => e
      puts "EXCEPTION:"
      puts e.inspect
      json_error 200, {error: 'invalid_signature', error_description: "There was an error verifying the signature. Please try again."}
    end

    # GPG signature was verified. Now decode and verify the JWT payload matches the expected request details.
    jwt_encoded = data.read
    begin
      payload = JWT.decode(jwt_encoded, SiteConfig.jwt_key)
      payload = payload[0]
    rescue JWT::DecodeError
      json_error 200, {error: 'decode_error', error_description: "There was an error with the signed text. Check that you signed the correct plaintext."}
    rescue 
      json_error 200, {error: 'decode_error', error_description: "There was an error with the signed text."}
    end

    if payload
      puts "Expected profile: #{expected['profile']}"
      jj payload

      # TODO: Expire the challenges after 5 minutes or so


      # Signature checked out, JWT token was successfully decoded
      # Now make sure that the profile_id referenced in the JWT was the same one that provided the public key
      if expected['profile'] == payload['profile']
        # Generate a login token
        redirect_uri = Login.build_redirect_uri({
          :me => payload['me'],
          :provider => 'gpg',
          :profile => expected['profile'],
          :redirect_uri => payload['redirect_uri'],
          :state => payload['state'],
          :scope => payload['scope']
        })

        # Redirect to the callback URL
        json_response 200, {redirect_uri: redirect_uri}
      else
        json_error 200, {error: 'verification_mismatch', error_description: "The challenge was signed with the wrong key."}
      end

    else
      json_error 200, {error: 'unknown_error', error_description: "Something went horribly wrong!"}
    end
  end

  post "/auth/verify_password.json" do
    message = params[:message]
    puts params[:signature]
    signature = RbNaCl::Util.hex2bin(params[:signature])
    public_key = RbNaCl::Util.hex2bin(params[:public_key])
    begin
      verify_key = RbNaCl::Signatures::Ed25519::VerifyKey.new(public_key)
      verification = verify_key.verify(signature, message)
    rescue RbNaCl::BadSignatureError => e
      json_error 200, {error: 'bad_signature', error_description: 'Could not verify signature'}
    end
    date = Time.at(message.to_i / 1000)
    if (Time.now - date) > 15
      json_error 200, {error: 'date_mismatch', error_description: "Signature was created in the past"}
    end

    redirect_uri = Login.build_redirect_uri({
      :provider => 'password',
      :redirect_uri => params[:redirect_uri],
    })

    json_response 200, {redirect_uri: redirect_uri}
  end

end