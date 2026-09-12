FROM alpine:3.23.3 AS build
RUN apk add --no-cache build-base linux-headers openssl-dev curl tar bzip2
WORKDIR /src
RUN curl -fLsS https://download.strongswan.org/strongswan-5.9.14.tar.bz2 -o source.tar.bz2 \
 && echo '728027ddda4cb34c67c4cec97d3ddb8c274edfbabdaeecf7e74693b54fc33678  source.tar.bz2' | sha256sum -c - \
 && tar -xjf source.tar.bz2
WORKDIR /src/strongswan-5.9.14
RUN CFLAGS="-O2 -Wno-error=incompatible-pointer-types" ./configure --prefix=/opt/strongswan --disable-defaults --enable-charon --enable-ikev2 --enable-vici --enable-swanctl \
 --enable-kdf --enable-openssl --enable-random --enable-nonce --enable-pem --enable-pkcs1 --enable-pubkey --enable-psk \
 --enable-eap-identity --enable-eap-mschapv2 --enable-md4 --enable-socket-default \
 --enable-kernel-netlink --enable-libipsec --enable-kernel-libipsec \
 && make -j4 && make install
FROM alpine:3.23.3
RUN apk add --no-cache openssl iproute2 iputils iptables
COPY --from=build /opt/strongswan /opt/strongswan
COPY strongswan.conf /opt/strongswan/etc/strongswan.conf
CMD ["/opt/strongswan/libexec/ipsec/charon"]
