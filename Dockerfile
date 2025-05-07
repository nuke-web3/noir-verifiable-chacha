# Use latest Ubuntu with glibc >= 2.38
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    curl \
    bash \
    git \
    jq \
    libstdc++6 \
    libc6 \
    && apt-get clean

RUN export NARGO_HOME=/root/.nargo HOME=/root && curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
RUN export BB_DIR=/root/.bb HOME=/root && curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash

ENV PATH="/root/.nargo/bin:/root/.bb:${PATH}"

RUN /root/.nargo/bin/noirup
RUN /root/.bb/bbup

COPY chacha20 /app/chacha20
COPY sha256 /app/sha256
COPY . /app/v-chacha

WORKDIR /app/v-chacha

RUN nargo execute

# TODO: get some proving backend stood up?
# I hope that the https://github.com/noir-lang/noir-runner would enable doing this...
# I think it's execution only?
# CMD ["bb", "prove", "-b", "./target/chacha20_example.json", "-w", "./target/chacha20_example.gz", "-o", "./"]
