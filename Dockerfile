FROM node:22-alpine AS deps

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-alpine AS runtime

WORKDIR /app
ENV NODE_ENV=production
ENV PDP_PORT=3000

COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=deps /app/dist ./dist
COPY mock-sources ./mock-sources

EXPOSE 3000
CMD ["node", "dist/main.js"]
