Encoding.default_internal = 'UTF-8'
require 'rubygems'
require 'bundler/setup'
require 'cgi'

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

class Controller < Sinatra::Base
  configure do

    register Sinatra::Namespace
    helpers  Sinatra::UserAgentHelpers

    # Set controller names so we can map them in the config.ru file.
    set :controller_names, []
    Dir.glob('controllers/*.rb').each do |file|
      settings.controller_names << File.basename(file, '.rb')
#      require_relative "./#{file}"
    end

    use Rack::Session::Cookie, :key => 'relmeauth',
                               :path => '/',
                               :expire_after => 2592000,
                               :domain => '.relmeauth.cc',
                               :secret => SiteConfig.session_secret

    set :root, File.dirname(__FILE__)
    set :show_exceptions, true
    set :raise_errors,    false

    use OmniAuth::Builder do
      provider :twitter,    SiteConfig.twitter.consumer_key,    SiteConfig.twitter.consumer_secret
      provider :foursquare, SiteConfig.foursquare.client_id,    SiteConfig.foursquare.client_secret
      provider :facebook,   SiteConfig.facebook.app_id,         SiteConfig.facebook.app_secret
      provider :geoloqi,    SiteConfig.geoloqi.api_key,         SiteConfig.geoloqi.api_secret
      provider :github,     SiteConfig.github.client_id,        SiteConfig.github.client_secret
      provider :google,     SiteConfig.google.client_id,        SiteConfig.google.client_secret
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
