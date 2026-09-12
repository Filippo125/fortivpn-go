FROM alpine:3.23.3
RUN apk add --no-cache strongswan iproute2 iputils curl python3
COPY strongswan.conf /etc/strongswan.conf
CMD ["/usr/lib/strongswan/charon"]
