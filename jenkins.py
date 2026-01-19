#!/usr/bin/env python3
"""Comprehensive Jenkins CLI tool for managing jobs, builds, queue, and nodes."""

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

    def _post(self, endpoint: str, params: Optional[Dict] = None, data: Optional[Dict] = None) -> requests.Response:
        """Make authenticated POST request to Jenkins API."""
        url = f"{self.base_url}{endpoint}"
        response = throttled_request(
            requests.post, url, auth=self.auth, params=params, data=data, timeout=30
        )
        return response

    # Jobs API methods
    def list_jobs(self, folder: Optional[str] = None) -> List[Dict]:
        """List all jobs, optionally within a folder."""
        if folder:
            endpoint = f"/job/{folder}/api/json"
        else:
            endpoint = "/api/json"
        params = {"tree": "jobs[name,url,color,description]"}
        try:
            data = self._get(endpoint, params)
            return data.get("jobs", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to list jobs: {e}")
            return []

    def get_job_info(self, job_name: str) -> Dict:
        """Get detailed information about a job."""
        endpoint = f"/job/{job_name}/api/json"
        params = {
            "tree": "name,url,description,color,buildable,inQueue,lastBuild[number,result,timestamp],"
                    "lastSuccessfulBuild[number,timestamp],lastFailedBuild[number,timestamp],"
                    "healthReport[description,score],property[parameterDefinitions[name,type,defaultParameterValue[value]]]"
        }
        try:
            return self._get(endpoint, params)
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get job info for '{job_name}': {e}")
            return {}

    def trigger_build(self, job_name: str, parameters: Optional[Dict] = None) -> Dict:
        """Trigger a new build for a job."""
        if parameters:
            endpoint = f"/job/{job_name}/buildWithParameters"
            response = self._post(endpoint, params=parameters)
        else:
            endpoint = f"/job/{job_name}/build"
            response = self._post(endpoint)

        # Jenkins returns 201 on successful queue
        if response.status_code in (200, 201):
            queue_url = response.headers.get("Location", "")
            return {"queued": True, "queue_url": queue_url}
        else:
            return {"queued": False, "status_code": response.status_code}

    def abort_build(self, job_name: str, build_number: int) -> Dict:
        """Abort a running build."""
        endpoint = f"/job/{job_name}/{build_number}/stop"
        try:
            response = self._post(endpoint)
            return {"aborted": response.status_code in (200, 302)}
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to abort build {job_name}#{build_number}: {e}")
            return {"aborted": False, "error": str(e)}

    # Builds API methods
    def get_job_builds(self, job_name: str, limit: int = 100) -> List[Dict]:
        """Get builds for a job, limited to most recent."""
        endpoint = f"/job/{job_name}/api/json"
        params = {"tree": f"builds[number,timestamp,duration,result,url,description]{{0,{limit}}}"}
        try:
            data = self._get(endpoint, params)
            return data.get("builds", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get builds for job '{job_name}': {e}")
            return []

    def get_build_info(self, job_name: str, build_number: int) -> Dict:
        """Get detailed information about a specific build."""
        endpoint = f"/job/{job_name}/{build_number}/api/json"
        params = {
            "tree": "number,url,result,timestamp,duration,estimatedDuration,building,"
                    "displayName,description,executor,actions[causes[shortDescription,userId],"
                    "parameters[name,value]]"
        }
        try:
            return self._get(endpoint, params)
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get build info for {job_name}#{build_number}: {e}")
            return {}

    def get_build_console_log(self, job_name: str, build_number: int) -> str:
        """Download console log for a specific build."""
        endpoint = f"/job/{job_name}/{build_number}/consoleText"
        try:
            return self._get_text(endpoint)
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get console log for {job_name}#{build_number}: {e}")
            return ""

    def list_artifacts(self, job_name: str, build_number: int) -> List[Dict]:
        """List artifacts for a specific build."""
        endpoint = f"/job/{job_name}/{build_number}/api/json"
        params = {"tree": "artifacts[fileName,relativePath,displayPath]"}
        try:
            data = self._get(endpoint, params)
            return data.get("artifacts", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to list artifacts for {job_name}#{build_number}: {e}")
            return []

    # Queue API methods
    def get_queue(self) -> List[Dict]:
        """Get the build queue."""
        endpoint = "/queue/api/json"
        params = {"tree": "items[id,task[name,url],why,inQueueSince,buildableStartMilliseconds,stuck]"}
        try:
            data = self._get(endpoint, params)
            return data.get("items", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get queue: {e}")
            return []

    def cancel_queue_item(self, queue_id: int) -> Dict:
        """Cancel a queued item."""
        endpoint = "/queue/cancelItem"
        try:
            response = self._post(endpoint, params={"id": queue_id})
            return {"cancelled": response.status_code in (200, 204, 302)}
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to cancel queue item {queue_id}: {e}")
            return {"cancelled": False, "error": str(e)}

    # Nodes API methods
    def list_nodes(self) -> List[Dict]:
        """List all nodes/agents."""
        endpoint = "/computer/api/json"
        params = {"tree": "computer[displayName,description,offline,offlineCause,numExecutors,idle,temporarilyOffline]"}
        try:
            data = self._get(endpoint, params)
            return data.get("computer", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to list nodes: {e}")
            return []

    def get_node_info(self, node_name: str) -> Dict:
        """Get detailed information about a node."""
        # Master node has special endpoint
        if node_name.lower() in ("master", "built-in"):
            endpoint = "/computer/(built-in)/api/json"
        else:
            endpoint = f"/computer/{node_name}/api/json"
        try:
            return self._get(endpoint)
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get node info for '{node_name}': {e}")
            return {}


# Command handlers

def cmd_jobs_list(args, client: JenkinsClient) -> Dict[str, Any]:
    """List all jobs."""
    jobs = client.list_jobs(folder=getattr(args, 'folder', None))

    job_list = []
    for job in jobs:
        name = job.get("name", "")
        if args.filter and args.filter.lower() not in name.lower():
            continue
        job_list.append({
            "name": name,
            "url": job.get("url"),
            "color": job.get("color"),
            "description": job.get("description"),
        })

    return {
        "jobs_count": len(job_list),
        "jobs": job_list,
    }


def cmd_jobs_info(args, client: JenkinsClient) -> Dict[str, Any]:
    """Get job details."""
    info = client.get_job_info(args.job)
    if not info:
        return {"error": f"Job '{args.job}' not found"}

    result = {
        "name": info.get("name"),
        "url": info.get("url"),
        "description": info.get("description"),
        "color": info.get("color"),
        "buildable": info.get("buildable"),
        "in_queue": info.get("inQueue"),
    }

    # Health report
    health = info.get("healthReport", [])
    if health:
        result["health"] = [{"score": h.get("score"), "description": h.get("description")} for h in health]

    # Last builds
    if info.get("lastBuild"):
        lb = info["lastBuild"]
        result["last_build"] = {
            "number": lb.get("number"),
            "result": lb.get("result"),
            "timestamp": datetime.fromtimestamp(lb.get("timestamp", 0) / 1000).isoformat() if lb.get("timestamp") else None,
        }

    if info.get("lastSuccessfulBuild"):
        lsb = info["lastSuccessfulBuild"]
        result["last_successful_build"] = {
            "number": lsb.get("number"),
            "timestamp": datetime.fromtimestamp(lsb.get("timestamp", 0) / 1000).isoformat() if lsb.get("timestamp") else None,
        }

    if info.get("lastFailedBuild"):
        lfb = info["lastFailedBuild"]
        result["last_failed_build"] = {
            "number": lfb.get("number"),
            "timestamp": datetime.fromtimestamp(lfb.get("timestamp", 0) / 1000).isoformat() if lfb.get("timestamp") else None,
        }

    # Parameters
    for prop in info.get("property", []):
        if prop.get("parameterDefinitions"):
            result["parameters"] = [
                {
                    "name": p.get("name"),
                    "type": p.get("type"),
                    "default": p.get("defaultParameterValue", {}).get("value") if p.get("defaultParameterValue") else None,
                }
                for p in prop["parameterDefinitions"]
            ]

    return result


def cmd_jobs_build(args, client: JenkinsClient) -> Dict[str, Any]:
    """Trigger a new build."""
    parameters = {}
    if args.param:
        for p in args.param:
            key, value = p.split("=", 1)
            parameters[key] = value

    result = client.trigger_build(args.job, parameters if parameters else None)
    result["job"] = args.job
    if parameters:
        result["parameters"] = parameters
    return result


def cmd_jobs_abort(args, client: JenkinsClient) -> Dict[str, Any]:
    """Abort a running build."""
    result = client.abort_build(args.job, args.build)
    result["job"] = args.job
    result["build"] = args.build
    return result


def cmd_builds_list(args, client: JenkinsClient) -> Dict[str, Any]:
    """List builds for a job."""
    builds = client.get_job_builds(args.job, limit=args.last if args.last else 100)

    build_list = []
    for build in builds:
        build_result = build.get("result")
        # Filter by status if specified
        if args.status and build_result != args.status.upper():
            continue

        timestamp_ms = build.get("timestamp", 0)
        build_time = datetime.fromtimestamp(timestamp_ms / 1000)

        # Filter by date if specified
        if args.date:
            date_filter = datetime.strptime(args.date, "%Y-%m-%d")
            if build_time.date() != date_filter.date():
                continue

        build_list.append({
            "number": build.get("number"),
            "result": build_result,
            "timestamp": build_time.isoformat(),
            "duration_ms": build.get("duration"),
            "url": build.get("url"),
            "description": build.get("description"),
        })

        if args.last and len(build_list) >= args.last:
            break

    return {
        "job": args.job,
        "builds_count": len(build_list),
        "builds": build_list,
    }


def cmd_builds_info(args, client: JenkinsClient) -> Dict[str, Any]:
    """Get build details."""
    info = client.get_build_info(args.job, args.build)
    if not info:
        return {"error": f"Build {args.job}#{args.build} not found"}

    result = {
        "job": args.job,
        "number": info.get("number"),
        "result": info.get("result"),
        "building": info.get("building"),
        "url": info.get("url"),
        "display_name": info.get("displayName"),
        "description": info.get("description"),
    }

    if info.get("timestamp"):
        result["timestamp"] = datetime.fromtimestamp(info["timestamp"] / 1000).isoformat()

    if info.get("duration"):
        result["duration_ms"] = info["duration"]
        result["duration_human"] = f"{info['duration'] / 1000:.1f}s"

    if info.get("estimatedDuration"):
        result["estimated_duration_ms"] = info["estimatedDuration"]

    # Extract causes and parameters from actions
    for action in info.get("actions", []):
        if action.get("causes"):
            result["causes"] = [
                {"description": c.get("shortDescription"), "user": c.get("userId")}
                for c in action["causes"]
            ]
        if action.get("parameters"):
            result["parameters"] = [
                {"name": p.get("name"), "value": p.get("value")}
                for p in action["parameters"]
            ]

    return result


def cmd_builds_log(args, client: JenkinsClient) -> Dict[str, Any]:
    """Fetch log for a specific build."""
    logger.info(f"Fetching log for {args.job}#{args.build}")

    console_log = client.get_build_console_log(args.job, args.build)
    log_lines = console_log.splitlines()

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(console_log, encoding="utf-8")
        logger.info(f"Saved log to {output_path}")
        return {
            "job": args.job,
            "build_number": args.build,
            "log_file": str(output_path),
            "line_count": len(log_lines),
        }
    else:
        return {
            "job": args.job,
            "build_number": args.build,
            "console_log": log_lines,
            "line_count": len(log_lines),
        }


def cmd_builds_artifacts(args, client: JenkinsClient) -> Dict[str, Any]:
    """List artifacts for a build."""
    artifacts = client.list_artifacts(args.job, args.build)

    return {
        "job": args.job,
        "build_number": args.build,
        "artifacts_count": len(artifacts),
        "artifacts": [
            {
                "filename": a.get("fileName"),
                "path": a.get("relativePath"),
            }
            for a in artifacts
        ],
    }


def cmd_queue_list(args, client: JenkinsClient) -> Dict[str, Any]:
    """View build queue."""
    items = client.get_queue()

    queue_list = []
    for item in items:
        task = item.get("task", {})
        queue_list.append({
            "id": item.get("id"),
            "job_name": task.get("name"),
            "job_url": task.get("url"),
            "why": item.get("why"),
            "stuck": item.get("stuck"),
            "in_queue_since": datetime.fromtimestamp(item.get("inQueueSince", 0) / 1000).isoformat() if item.get("inQueueSince") else None,
        })

    return {
        "queue_length": len(queue_list),
        "items": queue_list,
    }


def cmd_queue_cancel(args, client: JenkinsClient) -> Dict[str, Any]:
    """Cancel a queued item."""
    result = client.cancel_queue_item(args.id)
    result["queue_id"] = args.id
    return result


def cmd_nodes_list(args, client: JenkinsClient) -> Dict[str, Any]:
    """List all nodes/agents."""
    nodes = client.list_nodes()

    node_list = []
    for node in nodes:
        node_list.append({
            "name": node.get("displayName"),
            "description": node.get("description"),
            "executors": node.get("numExecutors"),
            "offline": node.get("offline"),
            "temporarily_offline": node.get("temporarilyOffline"),
            "idle": node.get("idle"),
        })

    return {
        "nodes_count": len(node_list),
        "nodes": node_list,
    }


def cmd_nodes_info(args, client: JenkinsClient) -> Dict[str, Any]:
    """Get node details."""
    info = client.get_node_info(args.node)
    if not info:
        return {"error": f"Node '{args.node}' not found"}

    return {
        "name": info.get("displayName"),
        "description": info.get("description"),
        "executors": info.get("numExecutors"),
        "offline": info.get("offline"),
        "temporarily_offline": info.get("temporarilyOffline"),
        "idle": info.get("idle"),
        "offline_cause": str(info.get("offlineCause")) if info.get("offlineCause") else None,
        "launch_supported": info.get("launchSupported"),
        "manual_launch_allowed": info.get("manualLaunchAllowed"),
    }


def cmd_failures(args, client: JenkinsClient) -> Dict[str, Any]:
    """Backwards compatibility: list failures for a job."""
    # Create a mock args object for builds list
    class BuildArgs:
        job = args.job
        status = "FAILURE"
        last = args.last
        date = args.date

    return cmd_builds_list(BuildArgs(), client)


def main():
    load_dotenv()

    # Parent parser for common options (inherited by all subparsers)
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )
    common_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    parser = argparse.ArgumentParser(
        description="Comprehensive Jenkins CLI tool for managing jobs, builds, queue, and nodes",
        parents=[common_parser],
    )

    subparsers = parser.add_subparsers(dest="group", help="Command group")

    # === Jobs Group ===
    jobs_parser = subparsers.add_parser("jobs", help="Manage Jenkins jobs", parents=[common_parser])
    jobs_sub = jobs_parser.add_subparsers(dest="action", help="Jobs action")

    # jobs list
    jobs_list = jobs_sub.add_parser("list", help="List all jobs", parents=[common_parser])
    jobs_list.add_argument("--folder", help="List jobs within a folder")
    jobs_list.add_argument("--filter", help="Filter jobs by name (case-insensitive)")

    # jobs info
    jobs_info = jobs_sub.add_parser("info", help="Get job details", parents=[common_parser])
    jobs_info.add_argument("job", help="Job name")

    # jobs build
    jobs_build = jobs_sub.add_parser("build", help="Trigger a new build", parents=[common_parser])
    jobs_build.add_argument("job", help="Job name")
    jobs_build.add_argument("-p", "--param", action="append", help="Build parameter (KEY=VALUE)")

    # jobs abort
    jobs_abort = jobs_sub.add_parser("abort", help="Abort a running build", parents=[common_parser])
    jobs_abort.add_argument("job", help="Job name")
    jobs_abort.add_argument("build", type=int, help="Build number")

    # === Builds Group ===
    builds_parser = subparsers.add_parser("builds", help="Manage build history", parents=[common_parser])
    builds_sub = builds_parser.add_subparsers(dest="action", help="Builds action")

    # builds list
    builds_list = builds_sub.add_parser("list", help="List builds for a job", parents=[common_parser])
    builds_list.add_argument("job", help="Job name")
    builds_list.add_argument("--status", help="Filter by status (SUCCESS, FAILURE, UNSTABLE, ABORTED)")
    builds_list.add_argument("-n", "--last", type=int, help="Show last N builds")
    builds_list.add_argument("-d", "--date", help="Show builds from specific date (YYYY-MM-DD)")

    # builds info
    builds_info = builds_sub.add_parser("info", help="Get build details", parents=[common_parser])
    builds_info.add_argument("job", help="Job name")
    builds_info.add_argument("build", type=int, help="Build number")

    # builds log
    builds_log = builds_sub.add_parser("log", help="Get console log", parents=[common_parser])
    builds_log.add_argument("job", help="Job name")
    builds_log.add_argument("build", type=int, help="Build number")
    builds_log.add_argument("-o", "--output", help="Save log to file")

    # builds artifacts
    builds_artifacts = builds_sub.add_parser("artifacts", help="List artifacts for a build", parents=[common_parser])
    builds_artifacts.add_argument("job", help="Job name")
    builds_artifacts.add_argument("build", type=int, help="Build number")

    # === Queue Group ===
    queue_parser = subparsers.add_parser("queue", help="Manage build queue", parents=[common_parser])
    queue_sub = queue_parser.add_subparsers(dest="action", help="Queue action")

    # queue list
    queue_sub.add_parser("list", help="View build queue", parents=[common_parser])

    # queue cancel
    queue_cancel = queue_sub.add_parser("cancel", help="Cancel a queued item", parents=[common_parser])
    queue_cancel.add_argument("id", type=int, help="Queue item ID")

    # === Nodes Group ===
    nodes_parser = subparsers.add_parser("nodes", help="Manage nodes/agents", parents=[common_parser])
    nodes_sub = nodes_parser.add_subparsers(dest="action", help="Nodes action")

    # nodes list
    nodes_sub.add_parser("list", help="List all nodes", parents=[common_parser])

    # nodes info
    nodes_info = nodes_sub.add_parser("info", help="Get node details", parents=[common_parser])
    nodes_info.add_argument("node", help="Node name")

    # === Failures (backwards compatibility) ===
    failures_parser = subparsers.add_parser("failures", help="List job failures (alias for builds list --status FAILURE)", parents=[common_parser])
    failures_parser.add_argument("job", help="Job name")
    failures_parser.add_argument("-n", "--last", type=int, help="Show last N failures")
    failures_parser.add_argument("-d", "--date", help="Show failures from specific date (YYYY-MM-DD)")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    # Show help if no command specified
    if not args.group:
        parser.print_help()
        sys.exit(0)

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
        result = None

        # Route to appropriate command handler
        if args.group == "jobs":
            if not args.action:
                jobs_parser.print_help()
                sys.exit(0)
            if args.action == "list":
                result = cmd_jobs_list(args, client)
            elif args.action == "info":
                result = cmd_jobs_info(args, client)
            elif args.action == "build":
                result = cmd_jobs_build(args, client)
            elif args.action == "abort":
                result = cmd_jobs_abort(args, client)

        elif args.group == "builds":
            if not args.action:
                builds_parser.print_help()
                sys.exit(0)
            if args.action == "list":
                result = cmd_builds_list(args, client)
            elif args.action == "info":
                result = cmd_builds_info(args, client)
            elif args.action == "log":
                result = cmd_builds_log(args, client)
            elif args.action == "artifacts":
                result = cmd_builds_artifacts(args, client)

        elif args.group == "queue":
            if not args.action:
                queue_parser.print_help()
                sys.exit(0)
            if args.action == "list":
                result = cmd_queue_list(args, client)
            elif args.action == "cancel":
                result = cmd_queue_cancel(args, client)

        elif args.group == "nodes":
            if not args.action:
                nodes_parser.print_help()
                sys.exit(0)
            if args.action == "list":
                result = cmd_nodes_list(args, client)
            elif args.action == "info":
                result = cmd_nodes_info(args, client)

        elif args.group == "failures":
            result = cmd_failures(args, client)

        if result:
            json_output = json.dumps(result, indent=2 if args.pretty else None, ensure_ascii=False)
            print(json_output)

    except Exception as e:
        logger.error(f"Error: {e}")
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
