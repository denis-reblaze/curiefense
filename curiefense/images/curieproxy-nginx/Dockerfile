#FROM docker.io/openresty/openresty:focal
FROM curieproxy-nginx
COPY default.conf /etc/nginx/conf.d/default.conf
CMD /usr/local/openresty/bin/openresty -sreload
