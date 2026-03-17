# Tiny mock JWKS server for e2e testing.
# Generates an RSA key pair at startup, serves the public key as JWKS,
# and exposes the private key via HTTP for the test runner.
FROM node:22-alpine
WORKDIR /app
COPY scripts/mock-jwks-server.ts ./server.ts
RUN npm init -y && npm install jose typescript @types/node && npx tsc --strict --target es2022 --module commonjs --esModuleInterop server.ts
EXPOSE 9877
CMD ["node", "server.js"]
