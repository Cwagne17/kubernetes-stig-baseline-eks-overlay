FROM debian:bookworm-slim

# Set metadata
LABEL maintainer="Christopher Wagner <github.com/Cwagne17>" \
      description="CINC Auditor with Kubernetes STIG Baseline EKS Overlay"

# Install all system dependencies, tools, and clean up in single layer
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        python3 \
        python3-pip \
        unzip \
    && curl -L https://omnitruck.cinc.sh/install.sh | bash -s -- -P cinc-auditor -v 6 \
    && SAF_VERSION=1.5.1 \
    && ARCH=$(dpkg --print-architecture) \
    && curl -L "https://github.com/mitre/saf/releases/download/${SAF_VERSION}/saf-${SAF_VERSION}-${ARCH}.deb" -o /tmp/saf.deb \
    && dpkg -i /tmp/saf.deb \
    && rm /tmp/saf.deb \
    && curl "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip" -o /tmp/awscliv2.zip \
    && unzip -q /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/aws /tmp/awscliv2.zip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python and Ruby dependencies (change less frequently than code)
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt \
    && /opt/cinc-auditor/embedded/bin/gem install train-awsssm --no-document \
    && rm /tmp/requirements.txt

# Copy profile code and setup (change most frequently - keep last)
WORKDIR /opt/profile
COPY . .
RUN chmod +x entrypoint.py && mkdir -p /opt/output

# Set environment variables
ENV OUTPUT_DIR=/opt/output

# Set entrypoint to Python script
ENTRYPOINT ["python3", "/opt/profile/entrypoint.py"]