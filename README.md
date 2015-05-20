IndieAuth
=========

IndieAuth is a way to use your own domain name to sign in to websites.

It works by linking your website to one or more authentication providers such as Twitter or Google, then entering your domain name in the login form on websites that support IndieAuth.

See more information and tutorials at [indieauth.com](https://indieauth.com/)


### Setup

Copy `config.yml.template` to `config.yml` and fill in all the details. You'll need to register OAuth apps at any of the providers you wish to support.

Bootstrap the database:

```
$ bundle exec rake db:bootstrap
```


### Contributing

By submitting code to this project, you agree to irrevocably release it under the same license as this project.


### License

Copyright 2015 by Aaron Parecki

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

