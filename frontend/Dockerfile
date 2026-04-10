# Stage 1: Build Next.js application
FROM node:20-alpine AS builder

WORKDIR /app

ARG BACKEND_URL
ENV BACKEND_URL=$BACKEND_URL

# Install dependencies (only copy package files for caching)
COPY package.json package-lock.json* ./
RUN npm ci || npm install --legacy-peer-deps

# Copy all files
COPY . .

# Next.js telemetry disable
ENV NEXT_TELEMETRY_DISABLED=1

# Build the application
# We use build-time env for BACKEND_URL if needed, but Next.js proxying usually happens at runtime for SSR/API
RUN npm run build

# Stage 2: Production runtime
FROM node:20-alpine AS runner

WORKDIR /app

ARG BACKEND_URL
ENV BACKEND_URL=$BACKEND_URL
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Copy built assets from builder
COPY --from=builder /app/package.json ./
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/next.config.ts ./

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Use npm start for production
CMD ["npm", "start"]
