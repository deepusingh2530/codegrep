FROM docker:24
RUN printf '{"insecure-registries":["registry.local"]}' > /etc/docker/daemon.json
