FROM node:lts AS base
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
EXPOSE 8192
CMD [ "node", "/app/dist" ]