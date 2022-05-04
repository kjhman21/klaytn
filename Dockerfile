# Global ARGs
ARG DOCKER_BASE_IMAGE=klaytn/build_base:latest
ARG PKG_DIR=/klaytn-docker-pkg
ARG SRC_DIR=/go/src/github.com/klaytn/klaytn

FROM ${DOCKER_BASE_IMAGE} AS builder
LABEL maintainer="Austin Brown <austin.brown@groundx.xyz>"
ARG SRC_DIR
ARG PKG_DIR

ARG KLAYTN_RACE_DETECT=0
ENV KLAYTN_RACE_DETECT=$KLAYTN_RACE_DETECT

ARG KLAYTN_STATIC_LINK=0
ENV KLAYTN_STATIC_LINK=$KLAYTN_STATIC_LINK

ARG KLAYTN_DISABLE_SYMBOL=0
ENV KLAYTN_DISABLE_SYMBOL=$KLAYTN_DISABLE_SYMBOL

ADD . $SRC_DIR
RUN cd $SRC_DIR && make all

FROM --platform=linux/amd64 alpine:3
ARG SRC_DIR
ARG PKG_DIR

RUN mkdir -p $PKG_DIR/conf $PKG_DIR/bin

# Add bash as required by the Klaytn startup scripts
RUN apk add --no-cache bash

# Startup scripts and binaries must be in the same location
COPY --from=builder $SRC_DIR/build/bin/* $PKG_DIR/bin/
COPY --from=builder $SRC_DIR/build/packaging/linux/bin/* $PKG_DIR/bin/
COPY --from=builder $SRC_DIR/build/packaging/linux/conf/* $PKG_DIR/conf/

ENV PATH=$PKG_DIR/bin:$PATH

EXPOSE 8551 8552 32323 61001 32323/udp
