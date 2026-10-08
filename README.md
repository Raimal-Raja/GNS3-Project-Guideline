# GNS3-Project-Guideline

GNS3 networking lab resources with a saved topology, routing and ACL guidance, shell commands, and an appliance definition.

## Setup and repository reference

### Project structure

- [Corporate_Network_(EnvironmentSetup).pdf](Corporate_Network_%28EnvironmentSetup%29.pdf)
- [LICENSE](LICENSE)
- [Topology.jpg](Topology.jpg)
- [alpine-linux.gns3a](alpine-linux.gns3a)
- [commands.sh](commands.sh)
- [requirements.txt](requirements.txt)
- [static-Routing-Acl.gns3](static-Routing-Acl.gns3)

### Getting started

```bash
git clone https://github.com/Raimal-Raja/GNS3-Project-Guideline.git
cd GNS3-Project-Guideline
```

Create and activate a virtual environment, then install the project dependencies:

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r "requirements.txt"
```

Browse the folders and linked notes above. This repository is a resource collection or documentation starter rather than a runnable application.

### Configuration and limitations

The tracked repository contains lab resources, not the Python ACL-manager application described in the older README. GNS3 topology execution requires the corresponding local appliances.

### Validation

Audit: 2026-10-08. Repository structure, setup instructions and description were reviewed. Syntax checks do not establish full runtime correctness. External APIs, live scraping, GUI interaction, notebook training and production deployment were not comprehensively exercised.

### Repository description

The short GitHub description is provided in [REPOSITORY_DESCRIPTION.md](REPOSITORY_DESCRIPTION.md).

### Contributions

Describe the issue, reproduction steps, environment, and expected behavior when proposing a change. Keep generated environments, credentials, and unnecessary build artifacts out of new commits.

### License

See [LICENSE](LICENSE) for the repository’s licensing terms.
