class Controller < Sinatra::Base

  get '/auth/send_sms.json' do
    me, profile, user, provider, profile_record, verified, error_description = auth_param_setup

    if provider.nil? or provider.code != 'sms'
      json_error 400, {error: 'invalid_input', error_description: 'parameter "profile" must be SMS'}
    end

    login = Login.create :user => user,
      :provider => provider,
      :profile => profile_record, 
      :complete => false,
      :token => Login.generate_token,
      :redirect_uri => params[:redirect_uri],
      :sms_code => Login.generate_sms_code

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
      json_error 400, {error: 'invalid_input', error_description: 'parameter "profile" must be SMS'}
    end

    login = Login.first :user => user,
      :provider => provider,
      :sms_code => params[:code],
      :complete => false

    # TODO: Check code creation date and disallow old stuff

    if login.nil?
      json_error 400, {error: 'invalid_code', error_description: 'The code could not be verified'}
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
          :redirect_uri => params[:redirect_uri]

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
      title "Set up Password-less Logins"
      return erb :totp_login
    end

    login = Login.first :token => params[:token]

    if login.nil?
      @message = "The token provided was not found"
      title "Error"
      return erb :error
    end

    if login.used_count > 0
      @message = "The token provided has already been used. Please <a href=\"/totp\">log in again</a>."
      title "Error"
      return erb :error
    end

    login.last_used_at = Time.now
    login.used_count = login.used_count + 1
    login.save

    @me = login.user
    title "Successfully Signed In!"

    # Upon successfully verifying their IndieAuth login:
    # * generate a TOTP secret
    # * store in the user record
    # * add a TOTP profile for the user so the button appears

    if @me.totp_secret.nil? or @me.totp_secret == ''
      ga = GoogleAuthenticator.new
      secret = ga.secret_key

      @me.totp_secret = secret
      @me.save
    else
      ga = GoogleAuthenticator.new @me.totp_secret
    end

    @qrcode = ga.qrcode_image_url "indieauth@#{@me[:href].sub(/https?:\/\//,'')}"

    profile = Profile.first_or_create({
      :user => @me,
      :provider => Provider.first(:code => 'totp')
    }, {
      :verified => true
    })

    erb :totp
  end

  get '/auth/verify_totp.json' do
    me = verify_me_param
    me = me.sub(/(\/)+$/,'')
    @user = User.first :href => me

    if @user.nil?
      json_error 400, {
        error: 'invalid_user',
        error_description: 'Profile was not found'
      }
    end

    if @user.totp_secret.nil? or @user.totp_secret == ''
      json_error 400, {
        error: 'not_supported',
        error_description: 'TOTP is not yet configured for this user'
      }
    end

    ga = GoogleAuthenticator.new @user.totp_secret
    if ga.key_valid? params[:code]

      profile = Profile.first_or_create({
        :user => @user, 
        :provider => Provider.first(:code => 'totp')
      }, {
        :verified => true
      })

      login = Login.create :user => @user,
        :provider => Provider.first(:code => 'totp'),
        :profile => profile,
        :complete => true,
        :token => Login.generate_token,
        :redirect_uri => params[:redirect_uri]

      redirect_uri = build_redirect_uri login

      json_response 200, {
        result: 'verified',
        redirect: redirect_uri
      }
    else
      json_response 200, {
        result: 'error'
      }
    end
  end

end