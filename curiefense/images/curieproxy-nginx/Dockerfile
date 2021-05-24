FROM docker.io/openresty/openresty:focal
COPY conf.d /etc/nginx/conf.d
COPY curieproxy/lua /lua
COPY curieproxy/lua/shared-objects/*.so /usr/local/lib/lua/5.1/
# override the hyperscan4 .so with the hyperscan5 .so
COPY curieproxy/lua/shared-objects/curiefense.hs5.so /usr/local/lib/lua/5.1/curiefense.so

COPY curieproxy/config /bootstrap-config/config

RUN apt-get install libhyperscan5
RUN mkdir /config && chmod a+rwxt /config
RUN rm -f /lua/session.lua && ln -s /lua/session_rust_nginx.lua /lua/session.lua
RUN openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 -subj "/C=fr/O=curiefense/CN=testsystem" -keyout /etc/ssl/certificate.key -out /etc/ssl/certificate.crt

#CMD /usr/local/openresty/bin/openresty -sreload
