FROM node:24-alpine AS build
WORKDIR /src
COPY package.json tsconfig.json tsconfig.app.json vite.config.ts index.html ./
COPY src ./src
RUN npm install --no-audit --no-fund && npm run build

FROM nginx:1.29-alpine
COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=build /src/dist /usr/share/nginx/html
RUN chown -R nginx:nginx /usr/share/nginx/html /var/cache/nginx /var/run
USER nginx
EXPOSE 8080 8443
HEALTHCHECK --interval=5s --timeout=3s --retries=30 CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

