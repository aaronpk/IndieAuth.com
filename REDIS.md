Redis
=====


## Email Codes

Email verification codes are cached temporarily in Redis using a simple key/value store.

The keys are of the pattern:

`indieauth::email::{url}`


## Cached Profiles

Once a user's profiles are discovered, they are cached in Redis for a period of time, to speed up the flow when they return.

`HSET indieauth::profile::{me} {profile} {data}`


## Logs

Logs are stored in a list, and flushed to the stats server periodically.

`RPUSH indieauth::logs {object}`


## App Census

Every app that completes a sign-in is recorded, so that `closed_to_new_apps`
can turn away apps never seen before without affecting the ones already
relying on this service.

`indieauth::client::{host}` = unix timestamp it was last seen

The host comes from the request's `redirect_uri`. Keys never expire: an app
that signed someone in years ago is still not a new adopter.

Recording happens whether or not the ratchet is switched on, so the census
fills up before it is needed. It only starts from the moment this is deployed,
though, so backfill it from the `logins` table first — otherwise turning the
ratchet on would refuse every app that had not happened to be used yet:

```sh
# Wherever the logins table is:
mysql -N -B indieauth -e "
  SELECT redirect_uri, MAX(created_at) FROM logins
  WHERE redirect_uri LIKE 'http%://%' GROUP BY redirect_uri" > clients.txt

# Wherever Redis is:
script/seed-client-census --dry-run < clients.txt
script/seed-client-census < clients.txt
```

Local, private and unreachable addresses are skipped, and running it again
leaves what is already there alone.
