FROM node:18
RUN npm ci --build-arg TARGET=builder
