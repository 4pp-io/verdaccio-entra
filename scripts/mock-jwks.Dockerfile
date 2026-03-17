# Tiny mock JWKS server for e2e testing.
# Generates an RSA key pair at startup, serves the public key as JWKS,
# and writes the private key + test metadata to /shared for the test runner.
FROM node:22-alpine
WORKDIR /app
COPY scripts/mock-jwks-server.mjs ./server.mjs
RUN npm init -y && npm install jose
EXPOSE 9877
CMD ["node", "server.mjs"]
