# A census of the apps that have successfully signed someone in here.
#
# IndieAuth.com is being replaced by two services, and the developer side of
# it — apps sending visitors here to be signed in — is replaced by
# IndieLogin.com. Closing that side to apps never seen before stops new
# adopters arriving while leaving the ones already relying on it alone.
#
# The record is written only when a sign-in completes, so an app refused by
# the ratchet can never register itself by being turned away. Recording
# happens whether or not the ratchet is switched on, so the census is already
# complete when it is.
class Client
  def self.key(host)
    "indieauth::client::#{host.to_s.downcase}"
  end

  def self.record(redirect_uri)
    host = host_of redirect_uri
    return if host.nil?

    R.set key(host), Time.now.to_i
  end

  def self.seen?(redirect_uri)
    host = host_of redirect_uri
    return false if host.nil?

    !R.get(key(host)).nil?
  end

  def self.host_of(redirect_uri)
    return nil if redirect_uri.nil? || redirect_uri.to_s == ''

    host = URI.parse(redirect_uri.to_s).host
    host.nil? || host == '' ? nil : host.downcase
  rescue StandardError
    nil
  end
end
