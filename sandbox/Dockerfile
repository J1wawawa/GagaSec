FROM alpine:3
ARG APK_MIRROR=https://dl-cdn.alpinelinux.org/alpine
RUN sed -i "s|https://dl-cdn.alpinelinux.org/alpine|${APK_MIRROR}|g" /etc/apk/repositories \
    && apk --timeout 15 add --no-cache strace tini
LABEL team.j4.gaga.runner="1"
USER 65534:65534
ENTRYPOINT ["/sbin/tini", "--"]
