# Was pinned to Node 20: node-fetch 2.x (via firebase-admin → google-auth-library
# → gaxios 6 → node-fetch 2.7) threw "Premature close" minting Google OAuth2
# access tokens on Node 22/24, which broke admin.auth() token mints (reset-link
# CLI + dashboard password reset). The pin is lifted because node-fetch 2 is now
# gone from the image entirely: firebase-admin 14 (modular API) pulls firestore 8
# → google-gax 5 → google-auth-library 10 → gaxios 7 → native fetch, and the last
# node-fetch 2 holdout, the unused optional @google-cloud/storage, is excluded in
# pnpm-workspace.yaml. Verify with:
#   pnpm why node-fetch   # must show only 3.x
FROM node:24 AS base
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"

# Install corepack and enable it
RUN npm install -g corepack@latest && corepack enable

WORKDIR /app
COPY package.json /app
COPY pnpm-lock.yaml /app
COPY .npmrc /app
COPY pnpm-workspace.yaml /app

# Install the exact pnpm version specified in package.json
# (kept in sync with the version in CasaOS-UI package.json)
RUN corepack install

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