FROM python:3-alpine

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PIP_NO_CACHE_DIR=off

WORKDIR /usr/src/crackmapexec

RUN apk update && \
    apk add --no-cache build-base libffi-dev libxml2-dev libxslt-dev openssl-dev openssl

COPY requirements.txt .

RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

RUN python setup.py install

ENTRYPOINT [ "cme" ]
