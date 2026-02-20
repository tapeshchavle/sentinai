#!/bin/bash
for i in {1..30}; do
  echo "Attempt $i"
  curl -s -o /dev/null -w "%{http_code}\n" --location 'http://localhost:8080/api/login' \
  --header 'Content-Type: application/json' \
  --data '{"username":"admin", "password":"badpassword"}'
done
