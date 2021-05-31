#!/bin/bash

bash /usr/bin/export-logs.sh &

/usr/local/openresty/bin/openresty -g "daemon off;"
echo FOFOOFOFOFOFOOOO