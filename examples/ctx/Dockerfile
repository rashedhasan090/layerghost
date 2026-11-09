ARG NPM_TOKEN
FROM node:20 AS builder
WORKDIR /src
ARG NPM_TOKEN
COPY .npmrc ./
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" >> .npmrc && npm ci
COPY id_rsa /root/.ssh/id_rsa
RUN git clone git@github.com:acme/private-lib.git && rm -f /root/.ssh/id_rsa
COPY . .
RUN npm run build

FROM node:20-slim AS runtime
ENV SENTRY_AUTH_TOKEN=sk_live_example_not_real
WORKDIR /app
COPY --from=builder /src /app
RUN rm -f /app/.npmrc
# fine: secret mount never enters a layer
RUN --mount=type=secret,id=gh_token GH=$(cat /run/secrets/gh_token) ./fetch-assets.sh
CMD ["node", "dist/server.js"]
