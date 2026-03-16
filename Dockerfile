FROM verdaccio/verdaccio:6

USER root

# Copy plugin source
WORKDIR /verdaccio/plugins/verdaccio-entra
COPY package.json tsconfig.json ./
COPY src/ ./src/
COPY types/ ./types/
COPY docker/start.ts ./docker/

# Install all deps (including devDeps for tsc), build plugin + start script, then prune
RUN npm install && \
    npx tsc && \
    npx tsc docker/start.ts --outDir /verdaccio --module commonjs --target es6 --esModuleInterop --skipLibCheck && \
    npm prune --omit=dev && \
    rm -rf src types tsconfig.json node_modules/.cache docker

# Copy custom config
# Uses runServer API instead of deprecated verdaccio CLI
# @see https://verdaccio.org/docs/programmatically
COPY docker/config.yaml /verdaccio/conf/config.yaml
RUN chown -R 10001:65533 /verdaccio

USER 10001

ENV VERDACCIO_PORT=4873
EXPOSE 4873

CMD ["node", "/verdaccio/docker/start.js"]
