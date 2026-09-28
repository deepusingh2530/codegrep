FROM rockylinux:9
RUN printf '[app]\nname=app\ngpgcheck=0\n' > /etc/yum.repos.d/app.repo
