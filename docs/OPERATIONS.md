# Operations Guide

## Overview

This document provides operational guidance for deploying and maintaining the Nocturne-KX cryptographic communication protocol in production environments.

## Prerequisites

### System Requirements

#### Hardware Requirements
- **CPU**: x86_64 or ARM64 processor
- **Memory**: Minimum 2GB RAM, 4GB recommended
- **Storage**: 10GB available disk space
- **Network**: Stable network connectivity

#### Software Requirements
- **Operating System**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+)
- **Kernel**: Linux kernel 4.18+
- **Compiler**: GCC 12+ or Clang 15+
- **Libraries**: libsodium 1.0.18+, OpenSSL 1.1.1+

#### Security Requirements
- **HSM**: PKCS#11 compatible HSM (recommended)
- **Key Management**: Secure key management system
- **Access Control**: Role-based access control
- **Audit Logging**: Comprehensive audit logging system

### Network Requirements

#### Network Security
- **Firewall**: Configured firewall rules
- **Network Segmentation**: Proper network segmentation
- **Intrusion Detection**: Network intrusion detection system
- **Traffic Analysis**: Network traffic analysis tools

#### Network Connectivity
- **Bandwidth**: Sufficient bandwidth for expected traffic
- **Latency**: Low latency for real-time communication
- **Reliability**: High availability network infrastructure
- **Redundancy**: Network redundancy for failover

## Installation

### Automated Installation

#### Using Package Manager
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y nocturne-kx

# CentOS/RHEL
sudo yum install -y nocturne-kx

# Arch Linux
sudo pacman -S nocturne-kx
```

#### Using Docker
```bash
# Pull the image
docker pull nocturne-kx:latest

# Run the container
docker run -d \
  --name nocturne-kx \
  -p 8080:8080 \
  -v /path/to/keys:/keys \
  -v /path/to/config:/config \
  nocturne-kx:latest
```

### Manual Installation

#### Building from Source
```bash
# Clone the repository
git clone https://github.com/your-org/nocturne-kx.git
cd nocturne-kx

# Install dependencies
sudo apt-get update
sudo apt-get install -y libsodium-dev pkg-config cmake build-essential

# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Install
sudo make install
```

#### Verifying Installation
```bash
# Check version
nocturne-kx --version

# Run self-test
nocturne-kx self-test

# Check dependencies
nocturne-kx check-deps
```

## Configuration

### Configuration Files

#### Main Configuration
```yaml
# /etc/nocturne-kx/config.yaml
server:
  host: "0.0.0.0"
  port: 8080
  max_connections: 1000
  timeout: 30

security:
  hsm:
    type: "pkcs11"
    library: "/usr/lib/libpkcs11.so"
    token_label: "nocturne-token"
    pin: "${HSM_PIN}"
  
  keys:
    rotation_interval: 86400  # 24 hours
    max_key_age: 604800      # 7 days
    min_key_size: 256
    
  replay_protection:
    enabled: true
    db_path: "/var/lib/nocturne-kx/replay.db"
    mac_key_path: "/etc/nocturne-kx/mac.key"
    max_skipped_messages: 1000

logging:
  level: "info"
  file: "/var/log/nocturne-kx/app.log"
  max_size: "100MB"
  max_files: 10
  
  audit:
    enabled: true
    file: "/var/log/nocturne-kx/audit.log"
    events: ["key_rotation", "authentication", "encryption", "decryption"]

monitoring:
  metrics:
    enabled: true
    port: 9090
    path: "/metrics"
  
  health_check:
    enabled: true
    port: 8081
    path: "/health"
```

#### HSM Configuration
```yaml
# /etc/nocturne-kx/hsm.yaml
pkcs11:
  library: "/usr/lib/libpkcs11.so"
  token_label: "nocturne-token"
  slot_id: 0
  
  authentication:
    pin: "${HSM_PIN}"
    so_pin: "${HSM_SO_PIN}"
    
  key_management:
    key_label_prefix: "nocturne-"
    key_type: "EC"
    curve: "P-256"
    
  session_management:
    max_sessions: 10
    session_timeout: 300
    auto_logout: true
```

### Environment Variables

#### Required Variables
```bash
# HSM Configuration
export HSM_PIN="your-hsm-pin"
export HSM_SO_PIN="your-hsm-so-pin"
export HSM_LIBRARY="/usr/lib/libpkcs11.so"

# Security Configuration
export NOCTURNE_SECRET_KEY="your-secret-key"
export NOCTURNE_MAC_KEY="your-mac-key"

# Database Configuration
export NOCTURNE_DB_PATH="/var/lib/nocturne-kx"
export NOCTURNE_REPLAY_DB="/var/lib/nocturne-kx/replay.db"
```

#### Optional Variables
```bash
# Logging Configuration
export NOCTURNE_LOG_LEVEL="info"
export NOCTURNE_LOG_FILE="/var/log/nocturne-kx/app.log"

# Network Configuration
export NOCTURNE_HOST="0.0.0.0"
export NOCTURNE_PORT="8080"

# Performance Configuration
export NOCTURNE_MAX_CONNECTIONS="1000"
export NOCTURNE_TIMEOUT="30"
```

### Key Management

#### Key Generation
```bash
# Generate receiver keys
nocturne-kx gen-receiver /etc/nocturne-kx/keys/

# Generate signer keys
nocturne-kx gen-signer /etc/nocturne-kx/keys/

# Generate HSM keys
nocturne-kx gen-hsm-keys \
  --hsm-config /etc/nocturne-kx/hsm.yaml \
  --key-label "nocturne-signer" \
  --key-type "Ed25519"
```

#### Key Rotation
```bash
# Manual key rotation
nocturne-kx rotate-keys \
  --config /etc/nocturne-kx/config.yaml \
  --force

# Check key status
nocturne-kx key-status \
  --config /etc/nocturne-kx/config.yaml

# Backup keys
nocturne-kx backup-keys \
  --config /etc/nocturne-kx/config.yaml \
  --backup-path /backup/keys/
```

## Deployment

### Systemd Service

#### Service File
```ini
# /etc/systemd/system/nocturne-kx.service
[Unit]
Description=Nocturne-KX Cryptographic Communication Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=nocturne-kx
Group=nocturne-kx
WorkingDirectory=/var/lib/nocturne-kx
ExecStart=/usr/bin/nocturne-kx server --config /etc/nocturne-kx/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/nocturne-kx /var/log/nocturne-kx

# Environment variables
Environment=HSM_PIN=your-hsm-pin
Environment=HSM_SO_PIN=your-hsm-so-pin
Environment=NOCTURNE_SECRET_KEY=your-secret-key

[Install]
WantedBy=multi-user.target
```

#### Service Management
```bash
# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable nocturne-kx
sudo systemctl start nocturne-kx

# Check status
sudo systemctl status nocturne-kx

# View logs
sudo journalctl -u nocturne-kx -f
```

### Docker Deployment

#### Docker Compose
```yaml
# docker-compose.yml
version: '3.8'

services:
  nocturne-kx:
    image: nocturne-kx:latest
    container_name: nocturne-kx
    ports:
      - "8080:8080"
      - "8081:8081"
      - "9090:9090"
    volumes:
      - /etc/nocturne-kx:/config:ro
      - /var/lib/nocturne-kx:/data
      - /var/log/nocturne-kx:/logs
    environment:
      - HSM_PIN=${HSM_PIN}
      - HSM_SO_PIN=${HSM_SO_PIN}
      - NOCTURNE_SECRET_KEY=${NOCTURNE_SECRET_KEY}
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETGID
      - SETUID

  hsm-proxy:
    image: hsm-proxy:latest
    container_name: hsm-proxy
    volumes:
      - /dev/hsm:/dev/hsm
    privileged: true
    restart: unless-stopped
```

#### Kubernetes Deployment
```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nocturne-kx
  labels:
    app: nocturne-kx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nocturne-kx
  template:
    metadata:
      labels:
        app: nocturne-kx
    spec:
      containers:
      - name: nocturne-kx
        image: nocturne-kx:latest
        ports:
        - containerPort: 8080
        - containerPort: 8081
        - containerPort: 9090
        env:
        - name: HSM_PIN
          valueFrom:
            secretKeyRef:
              name: nocturne-secrets
              key: hsm-pin
        - name: HSM_SO_PIN
          valueFrom:
            secretKeyRef:
              name: nocturne-secrets
              key: hsm-so-pin
        - name: NOCTURNE_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: nocturne-secrets
              key: secret-key
        volumeMounts:
        - name: config
          mountPath: /config
          readOnly: true
        - name: data
          mountPath: /data
        - name: logs
          mountPath: /logs
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8081
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8081
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: nocturne-config
      - name: data
        persistentVolumeClaim:
          claimName: nocturne-data
      - name: logs
        persistentVolumeClaim:
          claimName: nocturne-logs
```

## Monitoring

### Health Checks

#### Application Health
```bash
# Check application health
curl http://localhost:8081/health

# Check detailed health
curl http://localhost:8081/health/detailed

# Check HSM health
curl http://localhost:8081/health/hsm
```

#### System Health
```bash
# Check system resources
nocturne-kx system-health

# Check disk space
nocturne-kx check-disk

# Check memory usage
nocturne-kx check-memory
```

### Metrics

#### Prometheus Metrics
```bash
# View metrics
curl http://localhost:9090/metrics

# Key metrics to monitor:
# - nocturne_messages_encrypted_total
# - nocturne_messages_decrypted_total
# - nocturne_errors_total
# - nocturne_hsm_operations_total
# - nocturne_key_rotations_total
```

#### Grafana Dashboard
```json
{
  "dashboard": {
    "title": "Nocturne-KX Metrics",
    "panels": [
      {
        "title": "Message Throughput",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(nocturne_messages_encrypted_total[5m])",
            "legendFormat": "Encrypted/sec"
          },
          {
            "expr": "rate(nocturne_messages_decrypted_total[5m])",
            "legendFormat": "Decrypted/sec"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(nocturne_errors_total[5m])",
            "legendFormat": "Errors/sec"
          }
        ]
      }
    ]
  }
}
```

### Logging

#### Log Configuration
```yaml
# /etc/nocturne-kx/logging.yaml
version: 1
formatters:
  standard:
    format: '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
  audit:
    format: '%(asctime)s [AUDIT] %(name)s: %(message)s'

handlers:
  console:
    class: logging.StreamHandler
    level: INFO
    formatter: standard
    stream: ext://sys.stdout

  file:
    class: logging.handlers.RotatingFileHandler
    level: INFO
    formatter: standard
    filename: /var/log/nocturne-kx/app.log
    maxBytes: 10485760  # 10MB
    backupCount: 10

  audit:
    class: logging.handlers.RotatingFileHandler
    level: INFO
    formatter: audit
    filename: /var/log/nocturne-kx/audit.log
    maxBytes: 10485760  # 10MB
    backupCount: 10

loggers:
  nocturne:
    level: INFO
    handlers: [console, file]
    propagate: false

  nocturne.audit:
    level: INFO
    handlers: [audit]
    propagate: false

root:
  level: WARNING
  handlers: [console]
```

#### Log Analysis
```bash
# View application logs
tail -f /var/log/nocturne-kx/app.log

# View audit logs
tail -f /var/log/nocturne-kx/audit.log

# Search for errors
grep -i error /var/log/nocturne-kx/app.log

# Search for security events
grep -i "key rotation\|authentication\|encryption" /var/log/nocturne-kx/audit.log
```

## Maintenance

### Backup Procedures

#### Configuration Backup
```bash
# Backup configuration
sudo tar -czf /backup/nocturne-config-$(date +%Y%m%d).tar.gz \
  /etc/nocturne-kx/

# Backup keys
sudo tar -czf /backup/nocturne-keys-$(date +%Y%m%d).tar.gz \
  /var/lib/nocturne-kx/keys/

# Backup replay database
sudo cp /var/lib/nocturne-kx/replay.db \
  /backup/replay-$(date +%Y%m%d).db
```

#### Automated Backup Script
```bash
#!/bin/bash
# /usr/local/bin/backup-nocturne.sh

BACKUP_DIR="/backup/nocturne"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup configuration
tar -czf "$BACKUP_DIR/config-$DATE.tar.gz" /etc/nocturne-kx/

# Backup data
tar -czf "$BACKUP_DIR/data-$DATE.tar.gz" /var/lib/nocturne-kx/

# Backup logs
tar -czf "$BACKUP_DIR/logs-$DATE.tar.gz" /var/log/nocturne-kx/

# Clean old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

### Update Procedures

#### Software Updates
```bash
# Stop service
sudo systemctl stop nocturne-kx

# Backup current installation
sudo cp -r /usr/bin/nocturne-kx /usr/bin/nocturne-kx.backup

# Install new version
sudo make install

# Verify installation
nocturne-kx --version

# Start service
sudo systemctl start nocturne-kx

# Verify service
sudo systemctl status nocturne-kx
```

#### Configuration Updates
```bash
# Backup current configuration
sudo cp /etc/nocturne-kx/config.yaml /etc/nocturne-kx/config.yaml.backup

# Update configuration
sudo nano /etc/nocturne-kx/config.yaml

# Validate configuration
nocturne-kx validate-config /etc/nocturne-kx/config.yaml

# Reload service
sudo systemctl reload nocturne-kx
```

### Troubleshooting

#### Common Issues

##### Service Won't Start
```bash
# Check service status
sudo systemctl status nocturne-kx

# Check logs
sudo journalctl -u nocturne-kx -n 50

# Check configuration
nocturne-kx validate-config /etc/nocturne-kx/config.yaml

# Check dependencies
nocturne-kx check-deps
```

##### HSM Issues
```bash
# Check HSM connectivity
nocturne-kx hsm-status

# Test HSM operations
nocturne-kx hsm-test

# Check HSM logs
sudo journalctl -u hsm-proxy -f
```

##### Performance Issues
```bash
# Check resource usage
top -p $(pgrep nocturne-kx)

# Check network connections
netstat -tulpn | grep nocturne-kx

# Check disk I/O
iotop -p $(pgrep nocturne-kx)
```

#### Diagnostic Tools
```bash
# System diagnostics
nocturne-kx diagnose

# Performance profiling
nocturne-kx profile --duration 60

# Memory analysis
nocturne-kx memory-usage

# Network analysis
nocturne-kx network-stats
```

## Security

### Access Control

#### User Management
```bash
# Create service user
sudo useradd -r -s /bin/false nocturne-kx

# Set proper permissions
sudo chown -R nocturne-kx:nocturne-kx /var/lib/nocturne-kx
sudo chown -R nocturne-kx:nocturne-kx /var/log/nocturne-kx
sudo chmod 600 /etc/nocturne-kx/*.key
```

#### File Permissions
```bash
# Set secure permissions
sudo chmod 600 /etc/nocturne-kx/config.yaml
sudo chmod 600 /etc/nocturne-kx/hsm.yaml
sudo chmod 600 /var/lib/nocturne-kx/replay.db
sudo chmod 600 /var/lib/nocturne-kx/keys/*
```

### Audit Logging

#### Audit Configuration
```yaml
# /etc/nocturne-kx/audit.yaml
audit:
  enabled: true
  events:
    - key_rotation
    - authentication
    - encryption
    - decryption
    - hsm_operations
    - configuration_changes
  
  storage:
    type: "file"
    path: "/var/log/nocturne-kx/audit.log"
    max_size: "100MB"
    max_files: 10
  
  retention:
    days: 90
    compress: true
```

#### Audit Analysis
```bash
# View recent audit events
tail -f /var/log/nocturne-kx/audit.log

# Search for specific events
grep "key_rotation" /var/log/nocturne-kx/audit.log

# Generate audit report
nocturne-kx audit-report --days 7
```

### Incident Response

#### Incident Detection
```bash
# Monitor for security events
nocturne-kx security-monitor

# Check for anomalies
nocturne-kx anomaly-detection

# Alert on security events
nocturne-kx security-alerts
```

#### Incident Response Procedures
```bash
# 1. Isolate affected systems
sudo systemctl stop nocturne-kx

# 2. Preserve evidence
sudo cp /var/log/nocturne-kx/audit.log /evidence/
sudo cp /var/lib/nocturne-kx/replay.db /evidence/

# 3. Rotate keys
nocturne-kx emergency-key-rotation

# 4. Investigate
nocturne-kx security-analysis

# 5. Restore service
sudo systemctl start nocturne-kx
```

## Compliance

### Regulatory Compliance

#### FIPS 140-2/3
```bash
# Check FIPS compliance
nocturne-kx fips-check

# Enable FIPS mode
export OPENSSL_FIPS=1
nocturne-kx --fips-mode
```

#### GDPR Compliance
```bash
# Data retention policies
nocturne-kx retention-policy --days 90

# Data export
nocturne-kx export-data --user-id 12345

# Data deletion
nocturne-kx delete-data --user-id 12345
```

### Security Standards

#### NIST Cybersecurity Framework
- **Identify**: Asset inventory and risk assessment
- **Protect**: Access control and encryption
- **Detect**: Monitoring and alerting
- **Respond**: Incident response procedures
- **Recover**: Business continuity planning

#### ISO 27001
- **Information Security Management System**
- **Risk Assessment and Treatment**
- **Access Control**
- **Cryptography**
- **Incident Management**

## Support

### Documentation
- **User Guide**: [User Guide](USER_GUIDE.md)
- **API Reference**: [API Reference](API_REFERENCE.md)
- **Security Guide**: [Security Guide](SECURITY.md)
- **Troubleshooting**: [Troubleshooting](TROUBLESHOOTING.md)

### Contact Information
- **Technical Support**: support@your-org.com
- **Security Issues**: security@your-org.com
- **Documentation**: docs@your-org.com
- **Emergency**: +1-555-0123 (24/7)

### Community
- **GitHub Issues**: [GitHub Issues](https://github.com/your-org/nocturne-kx/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/nocturne-kx/discussions)
- **Wiki**: [GitHub Wiki](https://github.com/your-org/nocturne-kx/wiki)
