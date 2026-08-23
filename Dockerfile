FROM node:22-slim

ENV NODE_ENV=production
WORKDIR /app

# Dependencies first so the layer caches across source changes
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

# Run as the unprivileged user the base image ships with
USER node

# Cloud Run injects PORT; the server listens on process.env.PORT
EXPOSE 8080
CMD ["node", "server.js"]
