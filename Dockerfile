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
# Resource inventory truth: the PDP's opa-data resource provider reads the same
# zta.json that OPA loads, so OPA is the single source of resource truth.
COPY opa/data ./opa/data

EXPOSE 3000
CMD ["node", "dist/main.js"]
