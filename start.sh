#!/bin/bash

RACK_ENV=development bundle exec thin -p 9007 --threaded start
