#!/usr/bin/env python3
"""Query Jenkins job failures and download build logs."""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Rate limiting
RATE_LIMIT = 2  # requests per second
MIN_REQUEST_INTERVAL = 1 / RATE_LIMIT
last_request_time = 0


def throttled_request(method, url, **kwargs):
    """Make HTTP request with rate limiting and retry logic."""
    global last_request_time

    now = time.time()
    elapsed = now - last_request_time
    if elapsed < MIN_REQUEST_INTERVAL:
        time.sleep(MIN_REQUEST_INTERVAL - elapsed)

    last_request_time = time.time()

    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = method(url, **kwargs)

            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 5))
                logger.warning(f"Rate limited. Waiting {retry_after}s...")
                time.sleep(retry_after)
                last_request_time = time.time()
                continue

            if response.status_code >= 400:
                logger.error(f"HTTP {response.status_code}: {response.text}")
                if attempt < max_retries - 1:
                    time.sleep(2**attempt)
                    continue
                else:
                    response.raise_for_status()

            return response

        except requests.exceptions.RequestException as e:
            logger.error(f"Request error (attempt {attempt + 1}): {e}")
            if attempt < max_retries - 1:
                time.sleep(2**attempt)
            else:
                raise

    raise requests.exceptions.RequestException("Max retries exceeded")


class JenkinsClient:
    """Jenkins API client with authentication and rate limiting."""

    def __init__(self, url: str, user: str, token: str):
        self.base_url = url.rstrip("/")
        self.auth = (user, token)

    def _get(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """Make authenticated GET request to Jenkins API."""
        url = f"{self.base_url}{endpoint}"
        response = throttled_request(
            requests.get, url, auth=self.auth, params=params, timeout=30
        )
        return response.json()

    def _get_text(self, endpoint: str) -> str:
        """Make authenticated GET request and return text response."""
        url = f"{self.base_url}{endpoint}"
        response = throttled_request(
            requests.get, url, auth=self.auth, timeout=60
        )
        return response.text

    def get_job_builds(self, job_name: str, limit: int = 100) -> List[Dict]:
        """Get builds for a job, limited to most recent."""
        endpoint = f"/job/{job_name}/api/json"
        params = {"tree": f"builds[number,timestamp,duration,result,url]{{0,{limit}}}"}
        try:
            data = self._get(endpoint, params)
            return data.get("builds", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get builds for job '{job_name}': {e}")
            return []

    def get_build_console_log(self, job_name: str, build_number: int) -> str:
        """Download console log for a specific build."""
        endpoint = f"/job/{job_name}/{build_number}/consoleText"
        try:
            return self._get_text(endpoint)
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get console log for {job_name}#{build_number}: {e}")
            return ""


def get_failed_builds(builds: List[Dict], limit: Optional[int] = None, date: Optional[datetime] = None) -> List[Dict]:
    """Get failed builds, optionally filtered by limit or date."""
    failed = [b for b in builds if b.get("result") == "FAILURE"]

    if date:
        # Filter to builds on the specified date
        filtered = []
        for build in failed:
            timestamp_ms = build.get("timestamp", 0)
            build_time = datetime.fromtimestamp(timestamp_ms / 1000)
            if build_time.date() == date.date():
                filtered.append(build)
        return filtered

    if limit:
        return failed[:limit]

    return failed


def cmd_list(args, client: JenkinsClient) -> Dict[str, Any]:
    """List failures for a job."""
    logger.info(f"Checking job: {args.job}")
    builds = client.get_job_builds(args.job)

    date_filter = None
    if args.date:
        date_filter = datetime.strptime(args.date, "%Y-%m-%d")

    failed_builds = get_failed_builds(builds, limit=args.last, date=date_filter)

    failures = []
    for build in failed_builds:
        build_number = build.get("number")
        timestamp_ms = build.get("timestamp", 0)
        build_time = datetime.fromtimestamp(timestamp_ms / 1000)

        failures.append({
            "build_number": build_number,
            "timestamp": build_time.isoformat(),
            "duration_ms": build.get("duration"),
            "url": build.get("url"),
        })

    return {
        "job": args.job,
        "failures_found": len(failures),
        "failures": failures,
    }


def cmd_logs(args, client: JenkinsClient) -> Dict[str, Any]:
    """Fetch log for a specific build."""
    logger.info(f"Fetching log for {args.job}#{args.build}")

    console_log = client.get_build_console_log(args.job, args.build)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(console_log, encoding="utf-8")
        logger.info(f"Saved log to {output_path}")
        return {
            "job": args.job,
            "build_number": args.build,
            "log_file": str(output_path),
        }
    else:
        return {
            "job": args.job,
            "build_number": args.build,
            "console_log": console_log,
        }


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Query Jenkins job failures and download build logs"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # list command
    list_parser = subparsers.add_parser("list", help="List failures for a job")
    list_parser.add_argument("job", help="Jenkins job name")
    list_group = list_parser.add_mutually_exclusive_group()
    list_group.add_argument(
        "-n", "--last",
        type=int,
        default=None,
        help="Show last N failures",
    )
    list_group.add_argument(
        "-d", "--date",
        default=None,
        help="Show failures from specific date (YYYY-MM-DD)",
    )

    # logs command
    logs_parser = subparsers.add_parser("logs", help="Fetch log for a specific build")
    logs_parser.add_argument("job", help="Jenkins job name")
    logs_parser.add_argument("build", type=int, help="Build number")
    logs_parser.add_argument(
        "-o", "--output",
        default=None,
        help="Save log to file (prints to stdout if not specified)",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    jenkins_url = os.getenv("JENKINS_URL")
    jenkins_user = os.getenv("JENKINS_USER")
    jenkins_token = os.getenv("JENKINS_API_TOKEN")

    if not all([jenkins_url, jenkins_user, jenkins_token]):
        print(
            "Error: JENKINS_URL, JENKINS_USER, and JENKINS_API_TOKEN must be set",
            file=sys.stderr,
        )
        sys.exit(1)

    client = JenkinsClient(jenkins_url, jenkins_user, jenkins_token)

    try:
        if args.command == "list":
            result = cmd_list(args, client)
        elif args.command == "logs":
            result = cmd_logs(args, client)

        json_output = json.dumps(result, indent=2 if args.pretty else None, ensure_ascii=False)
        print(json_output)
    except Exception as e:
        logger.error(f"Error: {e}")
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
