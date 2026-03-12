---
interval: 45m
---

Check the build, build-arch and build-node-image jobs for any new failures since the last check. Check for currently running jobs


Create JIRA substasks for the new failures: be careful about: 
* ignore the 4.21-10.1 stream since it keeps failing and we will stop building it.
* The build-arch are triggered by the build jobs, therefore if a build-arch build fails and build job will also fail. We should create only 1 JIRA in that case, and track the build-arch failure.
