FROM docker:24
RUN printf '{"registry-mirrors":["https://mirror.local"]}' > /etc/docker/daemon.json
