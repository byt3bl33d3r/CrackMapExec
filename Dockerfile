FROM python:3.11-slim

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PIP_NO_CACHE_DIR=off

WORKDIR /usr/src/crackmapexec

RUN apt-get update && \
    apt-get install -y libffi-dev libxml2-dev libxslt-dev libssl-dev openssl autoconf g++ python3-dev curl git
RUN apt-get update
# Get Rust
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
# Add .cargo/bin to PATH
ENV PATH="/root/.cargo/bin:${PATH}"
# Check cargo is visible
RUN cargo --help

COPY . .
RUN pip install .

ENTRYPOINT [ "cme" ]
