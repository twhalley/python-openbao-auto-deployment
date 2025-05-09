# Use the latest Debian image
FROM debian:latest

ENV BAO_ADDR=https://127.0.0.1:8200

# Install necessary packages
RUN apt-get update
RUN apt-get install -y wget python3

# Install OpenBao (assuming it can be installed via a git repository)
RUN wget --https-only --secure-protocol=TLSv1_2 https://github.com/openbao/openbao/releases/download/v2.0.0-beta20240618/bao_2.0.0-beta20240618_linux_amd64.deb
RUN dpkg -i bao_2.0.0-beta20240618_linux_amd64.deb
RUN rm bao_2.0.0-beta20240618_linux_amd64.deb

# # Create raft dir
# RUN mkdir -p /opt/openbao/openbao_raft

# RUN ls -lrt /opt/openbao/openbao_ssl

# Change ownership of /opt/openbao to openbao user
RUN chown -R openbao:openbao /opt/openbao

# Change to the openbao user
USER openbao

# Copy the OpenBao configuration file to the container
COPY ./openbao_config /opt/openbao/openbao_config

# Copy the self signed SSL certs to the container
COPY ./openbao_ssl /opt/openbao/openbao_ssl

USER root

# Set permissions for SSL certs
RUN chmod 644 /opt/openbao/openbao_ssl/selfsigned.crt
RUN chmod 600 /opt/openbao/openbao_ssl/selfsigned.key

# Copy and update self signed to trusted cert on system
RUN cp /opt/openbao/openbao_ssl/selfsigned.crt /usr/local/share/ca-certificates/selfsigned.crt
RUN update-ca-certificates

USER openbao

# Copy the run script to the container
COPY ./runopenbao.sh /opt/openbao/runopenbao.sh

# Set permissions for script
RUN chmod +x /opt/openbao/runopenbao.sh

# Run the script
CMD [ "./runopenbao.sh" ]