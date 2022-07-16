FROM python:3.8-slim

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PIP_NO_CACHE_DIR=off

WORKDIR /usr/src/crackmapexec

RUN apt-get update && \
    apt-get install -y libffi-dev libxml2-dev libxslt-dev libssl-dev openssl autoconf g++ python3-dev libkrb5-dev git

COPY . .

RUN pip install .

ENTRYPOINT [ "cme" ]
