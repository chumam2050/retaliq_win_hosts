#!/usr/bin/env bash
# Simple curl test script for the HTTP receiver
# Usage: ./tools/test-curl.sh '["a.test","b.test"]'

JSON=${1:-'["test1.mydomain.test","test2.mydomain.test","test3.,mydomain.test"]'}

echo "Sending JSON: $JSON"

curl -v -X POST http://127.0.0.1:8888/hosts \
  -H "Content-Type: application/json" \
  --data-raw "$JSON"

echo
