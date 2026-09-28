FROM ubuntu:22.04
RUN echo 'deploy ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/deploy
