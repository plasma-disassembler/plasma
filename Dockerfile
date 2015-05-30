# Usage: docker run -h reverse -t -i reverse:latest
# >> load tests/nestedloop1.bin
# >> x

FROM ubuntu:14.04
MAINTAINER netantho@gmail.com

ENV LC_ALL C
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update --fix-missing

RUN apt-get -y install --no-install-recommends python3-pip git make gcc build-essential

RUN ln /usr/bin/python3.4 /usr/local/bin/python && \
    ln /usr/bin/pip3 /usr/local/bin/pip

ADD . /reverse

RUN /reverse/requirements.sh

WORKDIR /reverse
CMD python3.4 /reverse/reverse.py -i

