# Pinned to Node 20: node-fetch 2.x (via firebase-admin → google-auth-library →
# gaxios 6 → node-fetch 2.7) throws "Premature close" minting Google OAuth2
# access tokens on Node 22/24. The unpinned `node:lts` floated to 24 and broke
# admin.auth() token mints (reset-link CLI + dashboard password reset). Node 20
# is verified working with the same node_modules. Revisit when firebase-admin
# moves to gaxios 7 (native fetch).
FROM node:20 AS base
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable
#same version as the one in CasaOS-UI package.json
RUN corepack prepare pnpm@9.9.0 --activate

WORKDIR /app
COPY package.json /app
COPY pnpm-lock.yaml /app
COPY .npmrc /app

FROM base AS prod-deps
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --prod --frozen-lockfile

FROM base AS build
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --frozen-lockfile
COPY . /app
RUN pnpm run build

FROM base
# iputils-ping is required by /probe (Probe.ts shells out to `ping` to verify
# whether candidate IPs are reachable from the backend's vantage point). The
# Debian package's filecaps + Docker's default NET_RAW capability mean this
# works for non-root invocation without --cap-add at runtime.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping \
 && rm -rf /var/lib/apt/lists/*
COPY --from=prod-deps /app/node_modules /app/node_modules
COPY --from=build /app/dist /app/dist
# mesh-cli admin CLI shim (DAU KPIs) — see src/cli/index.ts
COPY ./bin/mesh-cli /usr/local/bin/mesh-cli
RUN chmod +x /usr/local/bin/mesh-cli
EXPOSE 8192
CMD [ "node", "/app/dist" ]