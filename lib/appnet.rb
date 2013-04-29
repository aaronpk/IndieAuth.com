module OmniAuth
  module Strategies
    class Appnet < OmniAuth::Strategies::OAuth2

      option :name, 'appnet'

      option :client_options, {
        :site => 'https://alpha-api.app.net',
        :authorize_url => 'https://alpha.app.net/oauth/authenticate',
        :token_url => 'https://alpha.app.net/oauth/access_token'
      }

      uid { raw_info['id'] }

      info do
        data = raw_info['data']
        {
          :nickname => data['username'],
          :name => data['name'],
          :image => data['avatar_image']['url'],
          :type => data['type'],
          :counts => data['counts']
        }
      end

      extra do
        { :raw_info => raw_info['data'] }
      end

      def raw_info
        @raw_info ||= access_token.get('stream/0/users/me').parsed
      end

    end
  end
end
