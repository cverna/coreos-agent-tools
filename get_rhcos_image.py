#!/usr/bin/env python3
"""
Outputs the data needed to get the RHCOS container image for a given OCP version.
"""
import argparse
import json
import logging
import os
import re
from datetime import datetime

import requests

logger = logging.getLogger(__name__)


def extract_all_ocp_versions():
    """
    Extract all OCP version names from the /graph endpoint.
    Returns:
        list: A list of version names
    """
    try:
        url = (
            "https://amd64.ocp.releases.ci.openshift.org/api/v1/releasestreams/accepted"
        )
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        versions = []
        if isinstance(data, dict):
            for base_version, version_list in data.items():
                if isinstance(version_list, list):
                    for version in version_list:
                        # Filter out release candidates
                        if not re.search(r"-rc\.\d+", version):
                            versions.append(version)

        def version_key(version):
            """
            Sorts a list by prioritizing date patterns first.
            - Returns (1, datetime_object) for date patterns.
            - Returns (0, version_tuple) for all other patterns.
            """
            # Check for the date pattern first (Priority 1)
            date_match = re.search(r"(\d{4}-\d{2}-\d{2}-\d{6})", version)
            if date_match:
                date_str = date_match.group(1)
                try:
                    date_obj = datetime.strptime(date_str, "%Y-%m-%d-%H%M%S")
                    # This is the highest priority group
                    return (1, date_obj)
                except ValueError:
                    pass  # Fall through if date is malformed

            # If no date is found, use your original logic (Priority 0)
            try:
                if "-ec." in version:
                    base, ec = version.split("-ec.")
                    major, minor, patch = map(int, base.split("."))
                    # Nest your original tuple inside the low priority group
                    return (0, (major, minor, patch, int(ec)))
                else:
                    parts = tuple(map(int, version.split(".")))
                    return (0, parts)
            except (ValueError, IndexError):
                # Fallback for unparseable strings like "nightly"
                return (0, (0, 0, 0, 0))

        def is_valid_ocp_version(version):
            """Check if version is OCP 4.12 or higher."""
            try:
                if not version.startswith("4."):
                    return False
                parts = version.split(".")
                if len(parts) < 2:
                    return False
                minor = int(parts[1])
                return minor >= 12
            except (ValueError, IndexError):
                return False

        filtered_versions = [v for v in versions if is_valid_ocp_version(v)]
        sorted_versions = sorted(filtered_versions, key=version_key, reverse=True)
        return sorted_versions
    except requests.exceptions.RequestException as e:
        logger.error(f"An error occurred fetching JSON data: {e}")
        return None
    except ValueError as e:
        logger.error(f"An error occurred parsing JSON data: {e}")
        return None


def get_latest_ocp_version() -> dict:
    """Get the latest OCP version for all OCP versions.
    Returns:
        dict: Mapping of major.minor versions to their latest z-stream versions.
    """
    all_versions = extract_all_ocp_versions() or []

    latest_versions = {}
    for version in all_versions:
        major_minor = ".".join(version.split(".")[:2])  # Get X.Y from X.Y.Z
        if major_minor not in latest_versions:
            latest_versions[major_minor] = version

    return latest_versions


def get_rhcos_image_data(ocp_version: str) -> dict:
    """
    Get the data needed to retrieve the RHCOS container image.

    Returns:
        dict: Dictionary containing:
            - release_image: The OCP release image
            - rhel_coreos: The RHEL CoreOS component name
            - registry_auth_file: Path to registry auth file (if set)
            - resolved_version: The full resolved OCP version
    """
    registry_auth_file = os.getenv("REGISTRY_AUTH_FILE")
    latest_ocp_versions = get_latest_ocp_version()

    if ocp_version not in latest_ocp_versions:
        return {
            "error": f"OCP version {ocp_version} not found in latest OCP versions",
            "available_versions": list(latest_ocp_versions.keys()),
        }

    resolved_version = latest_ocp_versions[ocp_version]

    # Determine RHEL CoreOS image name
    if "4.12" in resolved_version:
        rhel_coreos = "rhel-coreos-8"
    else:
        rhel_coreos = "rhel-coreos"

    # Determine the release image
    date_time_pattern = r"-\d{4}-\d{2}-\d{2}-\d{6}"

    if "konflux-nightly" in resolved_version:
        release_image = f"registry.ci.openshift.org/ocp/konflux-release:{resolved_version}"
    elif ("ci" in resolved_version or "nightly" in resolved_version) and re.search(
        date_time_pattern, resolved_version
    ):
        release_image = f"registry.ci.openshift.org/ocp/release:{resolved_version}"
    else:
        release_image = f"quay.io/openshift-release-dev/ocp-release:{resolved_version}-x86_64"

    result = {
        "release_image": release_image,
        "rhel_coreos": rhel_coreos,
        "resolved_version": resolved_version,
    }

    if registry_auth_file:
        result["registry_auth_file"] = registry_auth_file

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Get the data needed to retrieve the RHCOS container image"
    )
    parser.add_argument(
        "--ocp-version",
        type=str,
        required=True,
        help="OpenShift version (e.g., '4.12', '4.13')",
    )
    args = parser.parse_args()
    result = get_rhcos_image_data(args.ocp_version)
    print(json.dumps(result, indent=2))
