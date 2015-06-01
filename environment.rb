Encoding.default_internal = 'UTF-8'
require 'rubygems'
require 'bundler/setup'
require 'cgi'
require 'openid/store/memcache'

Bundler.require
Dir.glob(['lib', 'models', 'helpers'].map! {|d| File.join File.expand_path(File.dirname(__FILE__)), d, '*.rb'}).each {|f| require f}

unless File.exists? './config.yml'
  puts 'Please provide a config.yml file.'
  exit false
end

module RelMeAuth
  class SiteConfig < Hashie::Mash
    def key; self['key'] end
  end
end

SiteConfig = RelMeAuth::SiteConfig.new YAML.load_file('config.yml')[ENV['RACK_ENV']] if File.exists?('config.yml')

R = Redis.new :host => SiteConfig.redis.host, :port => SiteConfig.redis.port

class Controller < Sinatra::Base
  # before do
  #   puts "================================="
  #   puts request.env['REQUEST_PATH']
  #   jj params
  # end

  def self.get_or_post(url,&block)
    get(url,&block)
    post(url,&block)
  end

  configure do

    register Sinatra::Namespace
    helpers  Sinatra::UserAgentHelpers

    use Rack::Session::Cookie, :key => 'indieauth.com',
                               :path => '/',
                               :expire_after => 2592000,
                               :secret => SiteConfig.session_secret

    use Rack::Accept

    set :root, File.dirname(__FILE__)
    set :show_exceptions, true
    set :raise_errors,    true
    enable :logging

    use OmniAuth::Builder do
      SiteConfig.providers.each do |code, p|
        case code
        when 'google_oauth2'
          provider code.to_sym, p['client_id'], p['client_secret'], {access_type: 'online', approval_prompt: '', scope: 'profile,userinfo.profile,plus.me'} if p['client_id']
        when 'sms'
          # HI!
        else
          provider code.to_sym, p['client_id'], p['client_secret'] if p['client_id']
        end
      end
    end

    set :views, 'views'
    set :erubis,          :escape_html => true
    set :public_folder, File.dirname(__FILE__) + '/public'
  end

  def p; params end
end

require_relative './controller.rb'
Dir.glob(['controllers'].map! {|d| File.join d, '*.rb'}).each do |f| 
  require_relative f
end

scheduler = Rufus::Scheduler.new
scheduler.every '15s' do
  Log.flush
end
