FROM docker.io/openresty/openresty:focal
COPY conf.d /etc/nginx/conf.d
COPY curieproxy/lua /lua
COPY curieproxy/lua/shared-objects/*.so /usr/local/lib/lua/5.1/

COPY curieproxy/config /bootstrap-config/config

RUN mkdir /config && chmod a+rwxt /config

#CMD /usr/local/openresty/bin/openresty -sreload
