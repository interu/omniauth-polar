require "oauth2"
require "omniauth"
require "securerandom"
require "socket"       # for SocketError
require "timeout"      # for Timeout::Error

module OmniAuth
  module Strategies
    class Polar
      include OmniAuth::Strategy

      def self.inherited(subclass)
        OmniAuth::Strategy.included(subclass)
      end

      args %i[client_id client_secret]

      option :client_id, nil
      option :client_secret, nil
      option :client_options, {
        site: 'https://polarremote.com',
        authorize_url: 'https://flow.polar.com/oauth2/authorization',
        token_url: 'https://polarremote.com/v2/oauth2/token'
      }
      option :authorize_params, {
        response_type: 'code'
      }
      option :authorize_options, [:scope, :state]
      option :token_params, {}
      option :token_options, []
      option :auth_token_params, {}
      option :provider_ignores_state, false

      attr_accessor :access_token

      def client
        ::OAuth2::Client.new(options.client_id, options.client_secret, deep_symbolize(options.client_options))
      end

      credentials do
        hash = {"token" => access_token.token}
        hash["refresh_token"] = access_token.refresh_token if access_token.expires? && access_token.refresh_token
        hash["expires_at"] = access_token.expires_at if access_token.expires?
        hash["expires"] = access_token.expires?
        hash
      end

      def request_phase
        # Note: redirect_uri のパラーメータをつけると get_token で invalid_grant となるため
        redirect client.auth_code.authorize_url({}.merge(authorize_params))
      end

      def authorize_params
        options.authorize_params[:state] = SecureRandom.hex(24)
        params = options.authorize_params.merge(options_for("authorize"))
        if OmniAuth.config.test_mode
          @env ||= {}
          @env["rack.session"] ||= {}
        end
        session["omniauth.state"] = params[:state]
        params
      end

      uid { access_token.params["x_user_id"] }

      def token_params
        options.token_params.merge(options_for("token"))
      end

      def callback_phase # rubocop:disable AbcSize, CyclomaticComplexity, MethodLength, PerceivedComplexity
        error = request.params["error_reason"] || request.params["error"]
        if error
          fail!(error, CallbackError.new(request.params["error"], request.params["error_description"] || request.params["error_reason"], request.params["error_uri"]))
        elsif !options.provider_ignores_state && (request.params["state"].to_s.empty? || request.params["state"] != session.delete("omniauth.state"))
          fail!(:csrf_detected, CallbackError.new(:csrf_detected, "CSRF detected"))
        else
          self.access_token = build_access_token
          self.access_token = access_token.refresh! if access_token.expired?
          super
        end
      rescue ::OAuth2::Error, CallbackError => e
        fail!(:invalid_credentials, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

    protected

      def encode64_authorization_basic
        Base64.strict_encode64("#{options.client_id}:#{options.client_secret}")
      end

      def build_access_token
        verifier = request.params["code"]
        # headers = {
        #   headers: {
        #     "Authorization": "Basic #{encode64_authorization_basic}",
        #     "Accept": "application/json;charset=UTF-8"
        #   }
        # }
        # client.auth_code.get_token(verifier, headers.merge(token_params.to_hash(:symbolize_keys => true)), deep_symbolize(options.auth_token_params))

        # Note: client.auth_code.get_token(verifier, だと body に client_id と crient_secret が自動で付与され、
        #       invalid_request となるため独自実装に置き換え
        faraday_client = Faraday.new(url: 'https://polarremote.com') do |faraday|
          faraday.request  :url_encoded
          faraday.response :json
          faraday.adapter  Faraday.default_adapter
        end

        resp = faraday_client.post do |req|
          req.url "/v2/oauth2/token"
          req.headers['Authorization'] = "Basic #{encode64_authorization_basic}"
          req.headers["Content-Type"] = "application/x-www-form-urlencoded"
          req.headers["Accept"] = "application/json;charset=UTF-8"
          req.body = {
            :code=> verifier,
            :grant_type=>  "authorization_code",
          }
        end

        ::OAuth2::AccessToken.from_hash(faraday_client, resp.body)
      end

      def deep_symbolize(options)
        hash = {}
        options.each do |key, value|
          hash[key.to_sym] = value.is_a?(Hash) ? deep_symbolize(value) : value
        end
        hash
      end

      def options_for(option)
        hash = {}
        options.send(:"#{option}_options").select { |key| options[key] }.each do |key|
          hash[key.to_sym] = if options[key].respond_to?(:call)
            options[key].call(env)
          else
            options[key]
          end
        end
        hash
      end

      # An error that is indicated in the OAuth 2.0 callback.
      # This could be a `redirect_uri_mismatch` or other
      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(error, error_reason = nil, error_uri = nil)
          self.error = error
          self.error_reason = error_reason
          self.error_uri = error_uri
        end

        def message
          [error, error_reason, error_uri].compact.join(" | ")
        end
      end
    end
  end
end

OmniAuth.config.add_camelization "polar", "Polar"
