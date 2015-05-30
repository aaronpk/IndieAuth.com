class Controller < Sinatra::Base

  get '/auth/send_sms.json' do
    me, profile, user, provider, profile_record, verified, error_description = auth_param_setup

    if provider.nil? or provider.code != 'sms'
      json_error 200, {error: 'invalid_input', error_description: 'parameter "profile" must be SMS'}
    end

    login = Login.create :user => user,
      :provider => provider,
      :profile => profile_record, 
      :complete => false,
      :token => Login.generate_token,
      :redirect_uri => params[:redirect_uri],
      :sms_code => Login.generate_sms_code,
      :state => session[:state],
      :scope => session[:scope]

    # Send the SMS now!
    @twilio = Twilio::REST::Client.new SiteConfig.twilio.sid, SiteConfig.twilio.token
    @twilio.account.sms.messages.create(
      :from => SiteConfig.twilio.number,
      :to => profile_record.sms_number,
      :body => "Your IndieAuth verification code is: #{login.sms_code}"
    )

    json_response 200, {
      me: me, 
      profile: profile, 
      provider: provider.code,
      result: 'sent'
    }
  end

  get '/auth/verify_sms.json' do
    me, profile, user, provider, profile_record, verified, error_description = auth_param_setup

    if provider.nil? or provider.code != 'sms'
      json_error 200, {error: 'invalid_input', error_description: 'parameter "profile" must be SMS'}
    end

    login = Login.first :user => user,
      :provider => provider,
      :sms_code => params[:code],
      :complete => false

    # TODO: Check code creation date and disallow old stuff

    if login.nil?
      json_error 200, {error: 'invalid_code', error_description: 'The code could not be verified'}
    end

    login.complete = true
    login.save

    redirect_uri = build_redirect_uri login

    json_response 200, {
      me: me,
      profile: profile,
      provider: provider.code,
      result: 'verified',
      redirect: redirect_uri
    }
  end

  post '/auth/verify_email.json' do
    data = RestClient.post 'https://verifier.login.persona.org/verify', {
      :audience => SiteConfig.root,
      :assertion => params[:assertion]
    }
    response = JSON.parse data
    if response and response['status'] == 'okay'

      me = params[:me].sub(/(\/)+$/,'')
      me = "http://#{me}" unless me.match /^https?:\/\//

      user = User.first :href => me
      profile = user.profiles.first :href => "mailto:#{response['email']}"
      if profile.nil?
        json_error 200, {
          status: 'mismatch',
          reason: 'logged in as a different user'
        }
      else

        login = Login.create :user => user,
          :provider => Provider.first(:code => 'email'),
          :profile => profile,
          :complete => true,
          :token => Login.generate_token,
          :redirect_uri => params[:redirect_uri],
          :state => session[:state],
          :scope => session[:scope]

        redirect_uri = build_redirect_uri login

        json_response 200, {
          status: response['status'],
          email: response['email'],
          redirect: redirect_uri
        }
      end
    else
      json_error 200, {
        status: response['status'],
        reason: response['reason']
      }
    end
  end

  get '/totp' do
    if params[:token].nil?
      title "TOTP login is no longer supported"
      return erb :totp_login
    end
  end

  post '/auth/start_gpg.json' do
    me, profile, user, provider, profile_record, verified, error_description = auth_param_setup

    if provider.nil? or provider.code != 'gpg'
      json_error 200, {error: 'invalid_input', error_description: 'This profile must be a link to a GPG key'}
    end

    json_response 200, {
      plaintext: generate_gpg_challenge(me, user, profile_record, params),
      key_url: profile_record.href
    }
  end

  def generate_gpg_challenge(me, user, profile_record, params) 
    JWT.encode({
      :me => me,
      :user_id => user.id,
      :profile_id => profile_record.id,
      :redirect_uri => params[:redirect_uri],
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
    profile = Profile.get expected['profile_id'].to_i
    user = User.get expected['user_id'].to_i
    if profile.nil? or user.nil?
      json_error 200, {error: 'error', error_description: "Something went wrong, but this should never happen."}
    end

    puts "Expecting user #{user.href} (#{user.id}) to authenticate"

    begin
      agent = Mechanize.new {|agent|
        agent.user_agent_alias = "Mac Safari"
        # Default to text/html if content-type is not set
        agent.post_connect_hooks << lambda { |_,_,response,_|
          if response.content_type.nil? || response.content_type.empty?
            response.content_type = 'text/plain'
          end
        }
      }
      agent.agent.http.ca_file = './lib/ca-bundle.crt'
      # Use the key indicated by the signed JWT payload
      absolute = URI.join user.href, profile.href
      response = agent.get absolute
      public_key = response.body
    rescue => e
      json_error 200, {error: 'error_fetching_key', error_description: "There was an error fetching the key from #{profile.href}"}
    end

    verified = false

    # Verify the signature

    # The plaintext version is actually a JWT-signed payload that has all the info about the request
    # (me, redirect_uri, scope, etc)
    begin
      crypto = GPGME::Crypto.new

      # Import their public key 
      result = GPGME::Key.import(public_key)
      # Find the fingerprint of the key that was just imported (or had been previously imported)
      fingerprint = result.imports[0].fpr

      puts "Fingerprint of imported key: #{fingerprint}"

      signature = GPGME::Data.new(params[:signature])
      data = crypto.verify(signature) do |sig|
        puts sig.to_s
        verified = sig.valid?

        if !verified
          json_error 200, {error: 'invalid_signature', error_description: "The signature was invalid. Please try again."}
        end

        puts "Fingerprint of key that was used to sign: #{sig.fpr}"

        if fingerprint != sig.fpr
          json_error 200, {error: 'key_mismatch', error_description: "The key used to sign the challenge was not the key at #{absolute}."}
        end

      end
    rescue => e
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
      puts "Expected profile ID: #{profile.id}"
      jj payload

      # TODO: Expire the challenges after 5 minutes or so


      # Signature checked out, JWT token was successfully decoded
      # Now make sure that the profile_id referenced in the JWT was the same one that provided the public key
      if profile.id == payload['profile_id']
        # Generate a login token
        login = Login.create :user => User.get(payload['user_id'].to_i),
          :provider => Provider.first(:code => 'gpg'),
          :profile => Profile.get(payload['profile_id']),
          :complete => true,
          :token => Login.generate_token,
          :redirect_uri => payload['redirect_uri'],
          :state => payload['state'],
          :scope => payload['scope']

        # Redirect to the callback URL
        json_response 200, {redirect_uri: build_redirect_uri(login)}
      else
        json_error 200, {error: 'verification_mismatch', error_description: "The challenge was signed with the wrong key."}
      end

    else
      json_error 200, {error: 'unknown_error', error_description: "Something went horribly wrong!"}
    end
  end

end