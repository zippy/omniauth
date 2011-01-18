require 'omniauth/oauth'
require 'multi_json'

module OmniAuth
  module Strategies
    # Authenticate to MANAstats utilizing OAuth 2.0 and retrieve basic user information.

    class Manastats < OAuth2
      # @param [Rack Application] app standard middleware application parameter
      # @param [String] client_id the application id as registered as a client application on MANAstats
      # @param [String] client_secret the application secret as registered on MANAstats
      # @option options [String] :scope ('email,offline_access') comma-separated extended permissions such as `email` and `manage_pages`
      def initialize(app, client_id = nil, client_secret = nil, options = {}, &block)
        client_options = {
          :site => 'http://ms.local/',
          :authorize_path => '/oauth/authorize',
          :access_token_path => '/oauth/access_token'
        }
        super(app, :manastats, client_id, client_secret, client_options, options, &block)
      end
      
      def user_data
        @data ||= MultiJson.decode(@access_token.get('/oauth/user'))
      end
      
      def request_phase
#        options[:scope] ||= "email,offline_access"
        super
      end
      
      def user_info
        {
          'user_name' => user_data["user_name"],
          'email' => (user_data["email"] if user_data["email"]),
          'first_name' => user_data["first_name"],
          'last_name' => user_data["last_name"],
          'name' => "#{user_data['first_name']} #{user_data['last_name']}",
        }
      end
      
      def auth_hash
        OmniAuth::Utils.deep_merge(super, {
          'uid' => user_data['id'],
          'user_info' => user_info,
          'extra' => {'user_hash' => user_data}
        })
      end
    end
  end
end