FROM node:22-alpine
ARG ALPINE_MIRROR=https://dl-cdn.alpinelinux.org/alpine
RUN sed -i "s|https://dl-cdn.alpinelinux.org/alpine|${ALPINE_MIRROR}|g" /etc/apk/repositories \
    && (apk add --no-cache chromium font-noto-cjk || apk add --no-cache chromium font-noto-cjk) \
    && sed -i "s|${ALPINE_MIRROR}|https://dl-cdn.alpinelinux.org/alpine|g" /etc/apk/repositories
WORKDIR /opt/gaga-browser
COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY capture.mjs ./
ARG GAGA_BROWSER_SOURCE_SHA256
LABEL team.j4.gaga.browser="1"
LABEL team.j4.gaga.browser.source="${GAGA_BROWSER_SOURCE_SHA256}"
USER node
ENTRYPOINT ["node", "/opt/gaga-browser/capture.mjs"]
