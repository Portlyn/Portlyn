FROM --platform=$BUILDPLATFORM node:22-alpine AS base

RUN npm install -g npm@11.14.1

FROM base AS deps

WORKDIR /app

ARG NEXT_PUBLIC_API_BASE_URL=""
ARG INTERNAL_API_BASE_URL="http://portlyn:8080"
ENV NEXT_PUBLIC_API_BASE_URL=$NEXT_PUBLIC_API_BASE_URL
ENV INTERNAL_API_BASE_URL=$INTERNAL_API_BASE_URL

COPY package.json package-lock.json ./
RUN npm install --no-audit --no-fund

FROM base AS builder

WORKDIR /app

ARG NEXT_PUBLIC_API_BASE_URL=""
ARG INTERNAL_API_BASE_URL="http://portlyn:8080"
ENV NEXT_PUBLIC_API_BASE_URL=$NEXT_PUBLIC_API_BASE_URL
ENV INTERNAL_API_BASE_URL=$INTERNAL_API_BASE_URL

COPY --from=deps /app/node_modules ./node_modules
COPY . .

RUN npm run build

FROM base AS prodmodules

WORKDIR /app

ARG TARGETOS
ARG TARGETARCH

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund --cpu=${TARGETARCH} --os=${TARGETOS}

FROM node:22-alpine

WORKDIR /app

ARG NEXT_PUBLIC_API_BASE_URL=""
ARG INTERNAL_API_BASE_URL="http://portlyn:8080"
ENV NODE_ENV=production
ENV PORT=3000
ENV NEXT_PUBLIC_API_BASE_URL=$NEXT_PUBLIC_API_BASE_URL
ENV INTERNAL_API_BASE_URL=$INTERNAL_API_BASE_URL

RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx && \
    addgroup -S app && \
    adduser -S app -G app

COPY --from=builder --chown=app:app /app/package.json ./package.json
COPY --from=builder --chown=app:app /app/package-lock.json ./package-lock.json
COPY --from=prodmodules --chown=app:app /app/node_modules ./node_modules
COPY --from=builder --chown=app:app /app/.next ./.next
COPY --from=builder --chown=app:app /app/public ./public
COPY --from=builder --chown=app:app /app/next.config.mjs ./next.config.mjs

USER app

EXPOSE 3000

CMD ["node", "node_modules/next/dist/bin/next", "start"]
