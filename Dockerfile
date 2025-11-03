FROM redhat/ubi9:latest

# Set metadata
LABEL maintainer="Christopher Wagner <github.com/Cwagne17>" \
      description="CINC Auditor with Kubernetes STIG Baseline EKS Overlay"

# Install required packages
RUN dnf install -y \
    wget \
    tar \
    gzip \
    && dnf clean all

# Install CINC Auditor
RUN wget -O /tmp/cinc-auditor.tar.gz https://downloads.cinc.sh/files/stable/cinc-auditor/6.8.24/el/9/cinc-auditor-6.8.24-1.el9.x86_64.tar.gz \
    && tar -xzf /tmp/cinc-auditor.tar.gz -C /opt \
    && rm /tmp/cinc-auditor.tar.gz \
    && ln -s /opt/cinc-auditor/bin/cinc-auditor /usr/local/bin/cinc-auditor

# Create output directory
RUN mkdir -p /opt/output

# Copy the InSpec profile
COPY . /opt/profile

# Set working directory
WORKDIR /opt/profile

# Copy entrypoint script
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]