# kubernetes-stig-baseline-eks-overlay

[![validate](https://github.com/Cwagne17/kubernetes-stig-baseline-eks-overlay/actions/workflows/validate.yml/badge.svg)](https://github.com/Cwagne17/kubernetes-stig-baseline-eks-overlay/actions/workflows/validate.yml)
[![test](https://github.com/Cwagne17/kubernetes-stig-baseline-eks-overlay/actions/workflows/test.yml/badge.svg)](https://github.com/Cwagne17/kubernetes-stig-baseline-eks-overlay/actions/workflows/test.yml)
![STIG](https://img.shields.io/badge/Kubernetes_STIG-V2R4-blue)
[![Last Commit](https://img.shields.io/github/last-commit/Cwagne17/kubernetes-stig-baseline-eks-overlay)](https://github.com/Cwagne17/kubernetes-stig-baseline-eks-overlay/commits)
[![Open Issues](https://img.shields.io/github/issues/Cwagne17/kubernetes-stig-baseline-eks-overlay)](https://github.com/Cwagne17/kubernetes-stig-baseline-eks-overlay/issues)
[![License](https://img.shields.io/badge/License-Apache--2.0-green)](LICENSE)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-cwagne17-orange)](https://buymeacoffee.com/cwagne17)

Chef InSpec overlay implementing the **DISA Kubernetes STIG (V2R4)**, tailored for **Amazon EKS** clusters.  
This profile layers EKS-specific logic on top of the upstream Kubernetes STIG baseline—adding tailored inputs, helper resources, and documented exemptions for managed control-plane components.

## Quickstart

```bash
# Install CINC-auditor (recommended)
curl -L https://omnitruck.cinc.sh/install.sh | sudo bash -s -- -P cinc-auditor

# Fetch and run the profile
cinc-auditor exec https://github.com/Cwagne17/kubernetes-stig-baseline-eks-overlay \
  --input-file=examples/inputs.yml \
  --reporter cli json:report.json
```

Versioning policy: This repo mirrors the DISA STIG major/minor.  
STIG V2R4 → profile 2.4.x. We only bump patch for repo changes. When DISA releases a new major/minor, we align and tag accordingly.

## EKS-specific helpers

Custom resources live in `libraries/`:

- **aws_eks_cluster** – looks up an EKS cluster by name using `aws-sdk-eks`.
- **kubectl_client** – runs `kubectl` and returns parsed JSON or tabular output for control assertions.

## CI

- **validate**: syntax, style, dependency audit
- **test**: inspec check + example exec (dry, minimal env)
- **release**: manual (dispatch) release flow that enforces 2.4.x and generates changelog.

See `.github/workflows/*.yml`.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for branching, commit style, and release flow.  
Security issues: see [SECURITY.md](SECURITY.md).

## Support the project

If this overlay (or my other AWS/IaC/security tools) saves you time, consider supporting ongoing work:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-cwagne17-orange)](https://buymeacoffee.com/cwagne17)
