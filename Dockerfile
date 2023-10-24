FROM ubuntu:18.04


RUN echo "root:123456" | chpasswd

# clean files in .gitignore before building image

# develop: docker run -it --name test_jucify -v C:\JuCify\:/home/zhzhou/Jucify ubuntu:22.04
# headless jdk saves 300mb space
# "build-essential python3.7-dev graphviz libgraphviz-dev" is required for pygraphviz
SHELL ["/bin/bash", "-c"]

RUN sed -i "s/archive.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list \
 && sed -i "s/security.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list \
 && apt update && DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends git wget sudo software-properties-common nano maven openjdk-8-jdk-headless python3.7 python3.7-venv python3-pip python3.7-dev build-essential graphviz libgraphviz-dev unzip openssh-server \
 && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# 设置sshd
RUN sed -i "s/UsePAM.*/UsePAM no/g" /etc/ssh/sshd_config
RUN mkdir -p /var/run/sshd

RUN adduser zhzhou && \
    echo zhzhou:123456 | chpasswd &> /dev/null && \
    echo "zhzhou  ALL=(ALL) ALL" >> /etc/sudoers

USER zhzhou
WORKDIR /home/zhzhou

# Python env
RUN python3.7 -m venv jucify_venv \
 && echo source /home/zhzhou/jucify_venv/bin/activate >> /home/zhzhou/.bashrc \
 && source /home/zhzhou/jucify_venv/bin/activate \
 && python3.7 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple --upgrade pip \
 && python3.7 -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple \
 && python3.7 -m pip install wheel angr androguard==3.3.5 pygraphviz==1.7 protobuf==3.20.1

COPY [".", "/home/zhzhou/JuCify/"]
RUN echo 123456 | sudo -S chown -R zhzhou:zhzhou /home/zhzhou/JuCify/
RUN pip install -r requirements.txt

# build jucify jar
WORKDIR /home/zhzhou/JuCify
RUN /home/zhzhou/JuCify/build.sh
EXPOSE 22
CMD echo 123456 | sudo -S /usr/sbin/sshd -D &


