#!/bin/bash

RACK_ENV=development bundle exec shotgun -s thin -P public -p 9010
