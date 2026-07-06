FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci || npm install

COPY . .
# BACKEND_URL is baked into the rewrite at build time; override at build if needed.
ENV BACKEND_URL=http://backend:8000
RUN npm run build

# Run as the built-in non-root node user.
RUN chown -R node:node /app
USER node

EXPOSE 3000
CMD ["npm", "run", "start"]
