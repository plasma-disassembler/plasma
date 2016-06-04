# docker build -t plasma:latest .
# docker run --rm -ti plasma:latest

FROM ubuntu:16.04
MAINTAINER netantho@gmail.com

ENV LC_ALL C
ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm-256color

RUN apt-get update --fix-missing && apt-get -y install --no-install-recommends \
    python3-pip \
    python3-dev \
    python3-setuptools \
    python3-wheel \
    git \
    build-essential \
    sudo

ADD . /plasma
RUN cd /plasma && /plasma/install.sh

WORKDIR /plasma
ENTRYPOINT ["/plasma/run_plasma.py"]
