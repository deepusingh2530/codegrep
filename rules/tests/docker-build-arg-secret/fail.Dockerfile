FROM node:18
RUN npm ci --build-arg NODE_AUTH_TOKEN=${NPM_TOKEN}
