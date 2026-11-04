# Only a synthetic training runtime; entrypoint is explicitly overridden by the test.
FROM alpine:3.21
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk add --no-cache php83 procps \
    && ln -s /usr/bin/php83 /usr/local/bin/php
CMD ["/bin/false"]
