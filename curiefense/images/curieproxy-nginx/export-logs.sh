#/bin/bash

while true; do
  socat pipe:/nginx-accesslogs tcp4-connect:logstash:5000
  sleep 2
done
