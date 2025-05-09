# Python OpenBAO Auto Deployment

A Python-based deployment and configuration tool for OpenBAO (formerly known as Vault), providing secure secrets management and access control.

## Overview

This project provides a Python-based solution for deploying and configuring OpenBAO, including:
- Automated initialization and unsealing
- Policy creation and management
- AppRole authentication setup
- Database secrets engine configuration
- SSL/TLS certificate management
- Docker-based deployment
- Agent template example setup with PoC.

SSL certificate generation is done via OpenBAO.

## Prerequisites

- Docker and Docker Compose / Podman
- Python 3.x
- OpenSSL (for certificate generation)

## Project Structure

```
.
├── docker-compose.yml          # Docker Compose configuration
├── openbao/                    # OpenBAO configuration and deployment
│   ├── Dockerfile             # OpenBAO container definition
│   ├── openbao_deployment.py  # Main deployment script
│   ├── runopenbao.sh         # OpenBAO startup script
│   ├── openbao_config/       # Configuration files
│   ├── openbao_tls/         # TLS certificates
│   ├── openbao_ssl/         # SSL certificates
│   ├── openbao_data/        # Persistent data storage
│   └── openbao_log/         # Log files
```

## Features

- **Automated Deployment**: Streamlined deployment process using Docker Compose
- **SSL/TLS Support**: Built-in support for secure communication
- **Policy Management**: Automated policy creation and management
- **AppRole Authentication**: Secure service-to-service authentication
- **Database Integration**: PostgreSQL secrets engine configuration
- **Audit Logging**: Comprehensive audit trail support
- **No external libraries**: This does not use any libraies and is all done using Python 3.

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/python-openbao-deployment.git
   cd python-openbao-deployment
   ```

2. Build and start the containers:
   ```bash
   docker-compose up -d
   ```

3. Initialize OpenBAO:
   ```bash
   python openbao/openbao_deployment.py
   ```

## Configuration

### Environment Variables

- `BAO_ADDR`: OpenBAO server address (default: https://127.0.0.1:8200)
- `CA_BUNDLE_PATH`: Path to SSL certificate bundle

### SSL/TLS Configuration

Place your SSL certificates in the `openbao/openbao_ssl/` directory:
- `selfsigned.crt`: Self-signed certificate for development
- Additional certificates as needed

## Usage

### Basic Operations

1. **Initialize OpenBAO**:
   ```python
   init = initialize_openbao(verify_ssl=True)
   ```

2. **Unseal OpenBAO**:
   ```python
   unseal_vault(verify_ssl=True, unseal_key="your-unseal-key")
   ```

3. **Create Policies**:
   ```python
   create_policies(verify_ssl=True, root_token="your-root-token", service="service-name")
   ```

4. **Enable AppRole**:
   ```python
   enable_approle(verify_ssl=True, root_token="your-root-token", service="service-name")
   ```

## Security Considerations

- Always use SSL/TLS in production environments
- Securely store and manage root tokens and unseal keys
- Regularly rotate credentials and certificates
- Implement proper access controls and policies
- Monitor audit logs for suspicious activities

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the terms of the license included in the repository.

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.
