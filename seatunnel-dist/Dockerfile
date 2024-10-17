FROM docker.m.daocloud.io/library/openjdk:8u302-jdk

ENV SEATUNNEL_VERSION="2.3.7"
ENV SEATUNNEL_HOME="/opt/seatunnel"

WORKDIR /opt/

ADD target/apache-seatunnel-${SEATUNNEL_VERSION}-bin.tar.gz .

RUN mv apache-seatunnel-${SEATUNNEL_VERSION} ${SEATUNNEL_HOME} && \
    mkdir -p $SEATUNNEL_HOME/logs
# RUN cd ${SEATUNNEL_HOME} && sh bin/install-plugin.sh ${SEATUNNEL_VERSION}