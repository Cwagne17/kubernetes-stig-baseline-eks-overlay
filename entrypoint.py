#!/usr/bin/env python3
"""
EKS STIG Assessment Entrypoint

This script discovers EKS compute nodes and runs InSpec STIG assessments on both
the cluster and individual worker nodes, then converts results to CKL format.
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

import boto3
import yaml
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

name = "eks-stig-assessment"

# Setup logging
log_fmt = (
    "[%(asctime)s] %(levelname)s [%(filename)s.%(funcName)s:%(lineno)d] %(message)s"
)
date_fmt = "%Y-%m-%d %H:%M:%S"
logging.basicConfig(
    format=log_fmt, datefmt=date_fmt, handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(name)
logger.setLevel(logging.INFO)

# Global config - loaded once at startup
config: Optional["Config"] = None


# ============================================================================
# Dataclasses
# ============================================================================


@dataclass
class Config:
    """Configuration for EKS STIG assessment."""

    eks_cluster_name: str
    aws_region: str
    out_dir: Path
    timestamp: str
    max_parallel: int


@dataclass
class ComputeNode:
    """Represents an EKS compute node."""

    instance_id: str
    instance_type: str
    nodegroup_name: Optional[str] = None
    private_ip: Optional[str] = None
    state: str = "unknown"
    # ENI metadata for CKL generation
    hostname: Optional[str] = None
    private_dns_name: Optional[str] = None
    mac_address: Optional[str] = None


@dataclass
class NodeMetadata:
    """Metadata for a compute node used in CKL generation."""

    hostname: str
    hostip: str
    hostfqdn: str
    hostmac: str
    instance_id: str


# ============================================================================
# Configuration
# ============================================================================


def load_config() -> Config:
    """Load configuration from environment variables."""
    logger.info(f"Loading configuration from: {Path.cwd()}")

    def get_env(key: str, required: bool = True) -> Optional[str]:
        value = os.getenv(key)
        if required and value is None:
            raise ValueError(f"Environment variable {key} is required but not set.")
        return value

    return Config(
        eks_cluster_name=get_env("EKS_CLUSTER_NAME"),
        aws_region=get_env("AWS_REGION", False) or "us-east-1",
        out_dir=Path(get_env("OUTPUT_DIR", False) or "./output"),
        timestamp=datetime.now().strftime("%Y%m%d%H%M%S"),
        max_parallel=int(get_env("MAX_PARALLEL", False) or "3"),
    )


# ============================================================================
# AWS EKS Node Discovery
# ============================================================================


def get_eks_compute_nodes() -> List[ComputeNode]:
    """
    Discover all compute nodes for an EKS cluster using EC2 tags.

    EKS automatically tags all EC2 instances that join a cluster with:
    - Key: kubernetes.io/cluster/<cluster-name>
    - Value: owned
    """
    logger.info(f"Discovering compute nodes for EKS cluster: {config.eks_cluster_name}")

    try:
        eks_client = boto3.client("eks", region_name=config.aws_region)
        ec2_client = boto3.client("ec2", region_name=config.aws_region)

        # Verify cluster exists and is in ACTIVE state
        cluster_response = eks_client.describe_cluster(name=config.eks_cluster_name)
        cluster_status = cluster_response["cluster"]["status"]
        logger.info(f"Cluster status: {cluster_status}")

        if cluster_status != "ACTIVE":
            raise RuntimeError(
                f"Cluster '{config.eks_cluster_name}' is not in ACTIVE state (current: {cluster_status}). "
                "You must wait for the cluster to be ACTIVE before running assessments."
            )

        # Find all EC2 instances tagged with this cluster
        cluster_tag_key = f"kubernetes.io/cluster/{config.eks_cluster_name}"
        logger.info(f"Searching for running EC2 instances with tag: {cluster_tag_key}")

        ec2_response = ec2_client.describe_instances(
            Filters=[
                {"Name": f"tag:{cluster_tag_key}", "Values": ["owned"]},
                {"Name": "instance-state-name", "Values": ["running"]},
            ]
        )

        compute_nodes = []
        for reservation in ec2_response["Reservations"]:
            for instance in reservation["Instances"]:
                instance_id = instance["InstanceId"]

                # Extract nodegroup name from tags
                tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
                nodegroup_name = (
                    tags.get("eks:nodegroup-name") or tags.get("Name") or "unknown"
                )

                # Get the primary network interface (DeviceIndex 0)
                network_interfaces = instance["NetworkInterfaces"]
                primary_eni = next(
                    (
                        ni
                        for ni in network_interfaces
                        if ni["Attachment"]["DeviceIndex"] == 0
                    ),
                    None,
                )

                if not primary_eni:
                    raise RuntimeError(
                        f"No primary network interface found for instance {instance_id}"
                    )

                # Extract ENI metadata
                private_dns_name = primary_eni["PrivateDnsName"]
                hostname = private_dns_name.split(".")[0]
                mac_address = primary_eni["MacAddress"]

                node = ComputeNode(
                    instance_id=instance_id,
                    instance_type=instance["InstanceType"],
                    nodegroup_name=nodegroup_name,
                    private_ip=instance["PrivateIpAddress"],
                    state=instance["State"]["Name"],
                    hostname=hostname,
                    private_dns_name=private_dns_name,
                    mac_address=mac_address,
                )

                compute_nodes.append(node)
                logger.info(
                    f"  Node: {instance_id} ({instance['InstanceType']}, "
                    f"nodegroup: {nodegroup_name}, hostname: {hostname})"
                )

        logger.info(f"Successfully discovered {len(compute_nodes)} compute nodes")
        return compute_nodes

    except Exception as e:
        raise RuntimeError(
            f"Failed to discover compute nodes for EKS cluster '{config.eks_cluster_name}': {e}"
        ) from e


# ============================================================================
# Tool Validation
# ============================================================================


def which(cmd: str) -> str:
    """Check if a command-line tool is installed and return its path."""
    path = shutil.which(cmd)
    if not path:
        raise RuntimeError(f"Command '{cmd}' not found on PATH.")
    return path


def validate_required_tools() -> None:
    """Validate that all required tools are installed."""
    logger.info("Validating required tools...")

    required_tools = ["cinc-auditor", "saf"]
    for tool in required_tools:
        path = which(tool)
        logger.info(f"  ✓ {tool} found at: {path}")


def generate_kubeconfig() -> Path:
    """
    Generate a kubeconfig file for the EKS cluster using boto3.
    This is required for kubectl checks to work properly.

    Returns:
        Path to the kubeconfig file
    """
    kubeconfig_path = Path.home() / ".kube" / "config"
    kubeconfig_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info(f"Generating kubeconfig for cluster: {config.eks_cluster_name}")

    try:
        eks_client = boto3.client("eks", region_name=config.aws_region)

        # Get cluster details
        response = eks_client.describe_cluster(name=config.eks_cluster_name)
        cluster = response["cluster"]

        # Build kubeconfig structure
        kubeconfig = {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [
                {
                    "name": cluster["arn"],
                    "cluster": {
                        "server": cluster["endpoint"],
                        "certificate-authority-data": cluster["certificateAuthority"][
                            "data"
                        ],
                    },
                }
            ],
            "contexts": [
                {
                    "name": cluster["arn"],
                    "context": {
                        "cluster": cluster["arn"],
                        "user": cluster["arn"],
                    },
                }
            ],
            "current-context": cluster["arn"],
            "users": [
                {
                    "name": cluster["arn"],
                    "user": {
                        "exec": {
                            "apiVersion": "client.authentication.k8s.io/v1beta1",
                            "command": "aws",
                            "args": [
                                "eks",
                                "get-token",
                                "--cluster-name",
                                config.eks_cluster_name,
                                "--region",
                                config.aws_region,
                            ],
                        }
                    },
                }
            ],
        }

        # Write kubeconfig file
        with open(kubeconfig_path, "w") as f:
            yaml.dump(kubeconfig, f, default_flow_style=False)

        logger.info(f"  ✓ Kubeconfig generated at: {kubeconfig_path}")
        return kubeconfig_path

    except Exception as e:
        logger.error(f"Failed to generate kubeconfig: {e}")
        raise RuntimeError(f"Failed to generate kubeconfig: {e}") from e


# ============================================================================
# CKL Metadata
# ============================================================================


def filter_not_reviewed_controls(hdf_path: Path) -> None:
    """
    Remove controls that are skipped due to only_if guard conditions.
    Guards with messages containing 'cluster pass' or 'node pass' indicate scope-specific
    controls that should be filtered out when running the wrong scope.

    Args:
        hdf_path: Path to the HDF JSON file to filter
    """
    try:
        with open(hdf_path, "r") as f:
            data = json.load(f)

        # Filter out controls where only_if guard caused them to be skipped
        # Status is "skipped" with skip_message like "Skipped control due to only_if condition: node pass"
        for profile in data.get("profiles", []):
            original_count = len(profile.get("controls", []))
            filtered_controls = []

            for control in profile.get("controls", []):
                results = control.get("results", [])
                # Check if this control should be filtered
                # Look for status="skipped" with skip_message containing "cluster pass" or "node pass"
                is_guard_skipped = all(
                    result.get("status") == "skipped"
                    and (
                        "cluster pass" in result.get("skip_message", "")
                        or "node pass" in result.get("skip_message", "")
                    )
                    for result in results
                )

                # Keep control only if it's not guard-skipped
                if not is_guard_skipped:
                    filtered_controls.append(control)

            filtered_count = original_count - len(filtered_controls)
            profile["controls"] = filtered_controls

            if filtered_count > 0:
                logger.info(
                    f"  Filtered out {filtered_count} guard-skipped controls from {hdf_path.name}"
                )

        # Write back the filtered data
        with open(hdf_path, "w") as f:
            json.dump(data, f, indent=2)

    except Exception as e:
        logger.warning(f"Failed to filter controls from {hdf_path}: {e}")


def create_ckl_metadata(path: Path, node_metadata: NodeMetadata) -> None:
    """
    Create CKL metadata JSON file for SAF CLI conversion.

    Args:
        path: Path where metadata JSON file will be written
        node_metadata: NodeMetadata object containing node information
    """
    ckl_metadata = {
        "profiles": [
            {
                "name": "kubernetes-stig-baseline-eks-overlay",
                "title": "AWS EKS Kubernetes STIG Overlay :: Version 2, Release 4",
                "version": 2,
                "releasenumber": 4,
                "releasedate": "26 Jan 2024",
                "showCalendar": False,
            }
        ],
        "marking": "Unclass",
        "hostname": node_metadata.hostname,
        "hostip": node_metadata.hostip,
        "hostfqdn": node_metadata.hostfqdn,
        "hostmac": node_metadata.hostmac,
        "role": "Member Server",
        "assettype": "Computing",
        "techarea": "Container Platform",
        "stigguid": "CNTR-K8-000160",
        "webordatabase": "false",
        "vulidmapping": "gid",
        "webdbinstance": node_metadata.instance_id,
    }

    # Create metadata JSON file
    with open(path, "w") as f:
        json.dump(ckl_metadata, f, indent=4)

    logger.debug(f"Created CKL metadata file: {path}")


# ============================================================================
# Assessment Execution
# ============================================================================


async def run_cmd(argv: List[str], label: str, timeout: int = 600) -> int:
    """Run a command asynchronously with timeout."""
    logger.info(f"{label} Starting command {argv[0]}")

    popen_kwargs = {}
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["preexec_fn"] = os.setsid

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        **popen_kwargs,
    )
    try:
        rc = await asyncio.wait_for(proc.wait(), timeout=timeout)
        logger.info(f"{label} Command finished with return code: {rc}")
    except asyncio.TimeoutError:
        logger.error(f"{label} Command timed out after {timeout} seconds")
        proc.kill()
        rc = 124
    return rc


async def run_assessment(
    label: str,
    scope: str,
    target: str,
    hdf_path: Path,
    kubeconfig_path: Optional[Path] = None,
) -> Tuple[str, int, int]:
    """Run a single assessment (cluster or node) and convert to CKL."""
    # Validate tools are installed and get full paths
    cinc = which("cinc-auditor")
    saf = which("saf")

    # Build cinc-auditor command
    cinc_args = [
        cinc,
        "exec",
        ".",
        "--no-distinct-exit",
        "--reporter",
        f"json:{hdf_path}",
        "--input",
        f"run_scope={scope}",
        f"cluster_name={config.eks_cluster_name}",
        f"region={config.aws_region}",
    ]

    # Add kubeconfig input for cluster assessments
    if scope == "cluster" and kubeconfig_path:
        cinc_args.extend(["--input", f"kubeconfig={kubeconfig_path}"])

    # Add target for node assessments
    if scope == "node":
        cinc_args.extend(["--target", f"awsssm://{target}"])

    # Run assessment with 5 minute timeout
    cinc_rc = await run_cmd(cinc_args, f"[{label}][cinc-auditor]", timeout=300)

    # Filter out "Not Reviewed" controls from the JSON output
    filter_not_reviewed_controls(hdf_path)

    # Create metadata file if node metadata is provided (for node assessments)
    # TODO: Add metadata support for cluster assessments
    # metadata_path = None
    # if node_metadata:
    #     metadata_path = config.out_dir / f"{node_metadata.instance_id}_metadata.json"
    #     create_ckl_metadata(metadata_path, node_metadata)

    # Convert to CKL regardless of cinc return code
    saf_args = [
        saf,
        "convert",
        "hdf2ckl",
        "-i",
        str(hdf_path),
        "-o",
        str(hdf_path.with_suffix(".ckl")),
    ]

    # Add metadata if created (for node assessments)
    # if metadata_path and metadata_path.exists():
    #     saf_args.extend(["-M", str(metadata_path)])

    saf_rc = await run_cmd(saf_args, f"[{label}][saf]", timeout=60)

    # Clean up metadata file after conversion
    # if metadata_path and metadata_path.exists():
    #     os.remove(metadata_path)
    #     logger.debug(f"  Removed temporary metadata file: {metadata_path}")

    return (label, cinc_rc, saf_rc)


async def run_assessments_parallel(
    jobs: List[dict], max_parallel: int
) -> List[Tuple[str, int, int]]:
    """Run multiple assessments in parallel with semaphore limiting concurrency."""
    sem = asyncio.Semaphore(max_parallel)
    results = []

    async def worker(job):
        async with sem:
            return await run_assessment(**job)

    tasks = [asyncio.create_task(worker(j)) for j in jobs]
    for t in asyncio.as_completed(tasks):
        results.append(await t)
    return results


# ============================================================================
# Main Assessment Function
# ============================================================================


def eks_stig_assessment() -> int:
    """Main function to run EKS STIG assessments."""
    time_start = datetime.now()
    logger.info("Starting EKS STIG assessment")
    logger.info(f"EKS Cluster: {config.eks_cluster_name}")
    logger.info(f"AWS Region: {config.aws_region}")
    logger.info(f"Output Directory: {config.out_dir.absolute()}")

    # Generate kubeconfig for cluster assessments
    try:
        kubeconfig_path = generate_kubeconfig()
    except Exception as e:
        logger.error(f"Failed to generate kubeconfig: {e}")
        logger.warning("Cluster kubectl checks may fail without kubeconfig")
        kubeconfig_path = None

    # Discover compute nodes
    try:
        compute_nodes = get_eks_compute_nodes()
    except Exception as e:
        logger.error(f"Failed to discover compute nodes: {e}")
        logger.info("Will only run cluster assessment")
        compute_nodes = []

    # Build assessment jobs
    assessment_jobs = []

    # Add cluster assessment job with kubeconfig
    assessment_jobs.append(
        {
            "label": f"cluster:{config.eks_cluster_name}",
            "scope": "cluster",
            "target": config.eks_cluster_name,
            "hdf_path": config.out_dir
            / f"{config.eks_cluster_name}_cluster_{config.timestamp}.json",
            "kubeconfig_path": kubeconfig_path,
        }
    )

    # Add node assessment jobs
    for node in compute_nodes:
        # Simplified filename - just cluster name and instance ID
        assessment_jobs.append(
            {
                "label": f"node:{node.instance_id}",
                "scope": "node",
                "target": node.instance_id,
                "hdf_path": config.out_dir
                / f"{config.eks_cluster_name}_{node.instance_id}_{config.timestamp}.json",
                # Don't pass node_metadata - it may be causing CKL conversion issues
                # "node_metadata": node_metadata,
            }
        )

    logger.info(f"Created {len(assessment_jobs)} assessment jobs")

    # Run assessments in parallel
    results = asyncio.run(
        run_assessments_parallel(assessment_jobs, config.max_parallel)
    )

    time_end = datetime.now()
    logger.info(
        f"EKS STIG assessment completed. Outputs saved in {config.out_dir.absolute()}"
    )
    logger.info(f"Total assessment time: {time_end - time_start}")

    # Check if any assessment commands failed due to timeout (rc 124)
    timeout_cmd_failures = [
        label for label, cinc_rc, saf_rc in results if cinc_rc == 124 or saf_rc == 124
    ]
    if timeout_cmd_failures:
        logger.error(
            f"The following assessments timed out: {', '.join(timeout_cmd_failures)}"
        )

    # Keep non-zero exit if any SAF conversion failed; CINC is non-distinct by design
    any_saf_fail = any(saf_rc != 0 for _, _, saf_rc in results)
    return 1 if any_saf_fail or timeout_cmd_failures else 0


# ============================================================================
# Entry Point
# ============================================================================


if __name__ == "__main__":
    # Load config as global
    config = load_config()

    # Create output directory if it doesn't exist
    config.out_dir.mkdir(parents=True, exist_ok=True)

    try:
        validate_required_tools()
        rc = eks_stig_assessment()
    except RuntimeError as e:
        logger.critical(f"Fatal error occurred: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Assessment interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)

    # Clean up the output directory by removing JSON files
    logger.info("Cleaning up temporary HDF JSON files...")
    for json_file in config.out_dir.glob("*.json"):
        os.remove(json_file)
        logger.info(f"Removed: {json_file}")

    sys.exit(rc)
