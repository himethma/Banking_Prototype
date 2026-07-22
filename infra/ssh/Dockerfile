FROM alpine:3.22
RUN apk add --no-cache openssh-server openssh-sftp-server shadow \
 && mkdir -p /run/sshd /srv/storage /var/log/bastion
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
EXPOSE 2222
ENTRYPOINT ["/entrypoint.sh"]

