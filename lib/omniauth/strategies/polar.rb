require "oauth2"
require "omniauth"
require "omniauth-oauth2"

module OmniAuth
  module Strategies
    class Polar < OmniAuth::Strategies::OAuth2
      option :client_options, {
        site: 'https://polarremote.com',
        authorize_url: 'https://flow.polar.com/oauth2/authorization',
        token_url: 'https://polarremote.com/v2/oauth2/token',
        auth_scheme: :basic_auth
      }
      option :authorize_params, {
        response_type: 'code'
      }

      def build_access_token
        verifier = request.params["code"]
        client.auth_code.get_token(verifier, {}.merge(token_params.to_hash(:symbolize_keys => true)), deep_symbolize(options.auth_token_params))
      end

      def request_phase
        # Note: redirect_uri のパラーメータをつけると get_token で invalid_grant となるため
        redirect client.auth_code.authorize_url({}.merge(authorize_params))
      end

      uid { access_token.params["x_user_id"] }
    end
  end
end

OmniAuth.config.add_camelization "polar", "Polar"
