# Tiny mock JWKS server for e2e testing.
# Generates an RSA key pair at startup, serves the public key as JWKS,
# and exposes the private key via HTTP for the test runner.
FROM node:22-alpine
WORKDIR /app
COPY scripts/mock-jwks/package.json scripts/mock-jwks/package-lock.json ./
RUN npm ci
COPY scripts/mock-jwks-server.ts ./server.ts
RUN npx tsc --strict --target es2022 --module commonjs --esModuleInterop server.ts
EXPOSE 9877
CMD ["node", "server.js"]
