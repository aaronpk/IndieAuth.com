def init(env=ENV['RACK_ENV']); end
require File.join('.', 'environment.rb')

namespace :db do
  task :bootstrap do
    init
    DataMapper.auto_migrate!

    facebook = Provider.create ({
          :code => 'facebook',
          :client_id => SiteConfig.facebook.app_id,
          :client_secret => SiteConfig.facebook.app_secret,
          :regex_username => 'https?:\/\/(?:www\.)?facebook\.com\/([^\/]+)'
        })

    flickr = Provider.create ({
          :code => 'flickr',
          :client_id => SiteConfig.flickr.api_key,
          :client_secret => SiteConfig.flickr.api_secret,
          :regex_username => 'https?:\/\/(?:www\.)?flickr\.com\/(?:photos\/)?([^\/]+)'
        })

    geoloqi = Provider.create ({
          :code => 'geoloqi',
          :client_id => SiteConfig.geoloqi.api_key,
          :client_secret => SiteConfig.geoloqi.api_secret,
          :regex_username => 'https?:\/\/(?:www\.)?geoloqi\.com\/([^\/]+)'
        })

    github = Provider.create ({
          :code => 'github',
          :client_id => SiteConfig.github.client_id,
          :client_secret => SiteConfig.github.client_secret,
          :regex_username => 'https?:\/\/(?:www\.)?github\.com\/([^\/]+)'
        })

    google = Provider.create ({
          :code => 'google',
          :client_id => SiteConfig.google.client_id,
          :client_secret => SiteConfig.google.client_secret,
          :regex_username => 'https?:\/\/(?:www\.)?profiles\.google\.com\/([^\/]+)'
        })

    twitter = Provider.create ({
          :code => 'twitter',
          :client_id => SiteConfig.twitter.consumer_key,
          :client_secret => SiteConfig.twitter.consumer_secret,
          :regex_username => 'https?:\/\/(?:www\.)?twitter\.com\/([^\/]+)'
        })

    appnet = Provider.create ({
          :code => 'appnet',
          :client_id => SiteConfig.appnet.client_id,
          :client_secret => SiteConfig.appnet.client_secret,
          :regex_username => 'https?:\/\/alpha\.app\.net\/([^\/]+)'
        })

    sms = Provider.create ({
          :code => 'sms'
        })

    email = Provider.create ({
          :code => 'email'
        })

  end
  task :migrate do
    init
    DataMapper.auto_upgrade!
  end
end

