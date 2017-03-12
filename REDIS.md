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
