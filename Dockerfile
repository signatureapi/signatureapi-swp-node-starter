# SWP/1 signing worker. Node 24 runs the TypeScript sources directly (type stripping): no build step.
FROM node:24.14.1-bookworm-slim

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

COPY src ./src

# One SQLite file on a volume. Run one container per volume (see "Scaling" in the README).
RUN mkdir -p /data && chown node:node /data
VOLUME ["/data"]
ENV PORT=8080 DATABASE_PATH=/data/worker.sqlite

USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["node", "-e", "fetch(`http://127.0.0.1:${process.env.PORT}/v1/health`).then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "--disable-warning=ExperimentalWarning", "src/server.ts"]
