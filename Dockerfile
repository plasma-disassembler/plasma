# Usage: docker run -h plasma -t -i plasma:latest
# >> load tests/nestedloop1.bin
# >> x

FROM ubuntu:14.04
MAINTAINER netantho@gmail.com

ENV LC_ALL C
ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm-256color

RUN apt-get update --fix-missing

RUN apt-get -y install --no-install-recommends python3-pip \
    python3-dev \
    git \
    make \
    gcc \
    build-essential

RUN ln /usr/bin/python3.4 /usr/local/bin/python && \
    ln /usr/bin/pip3 /usr/local/bin/pip

ADD . /plasma

RUN pip3 install future
RUN /plasma/install.sh

WORKDIR /plasma
CMD python3 /plasma/plasma.py -i

