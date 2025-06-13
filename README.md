# Aphelion Agent Security Framework

🚀 **Project Status**: In active development. All components subject to change. Contributions and feedback welcome.

🎯 **Intent**: Simplify and strengthen security for AI agents, tool interactions, and data access across workflows and environments. Provide a lightweight, user-friendly solution for hobbyists, small businesses, and enterprises.

🛠️ **Goals**:
- Simplify Integration
- Enhance Security
- Broad Applicability
- Configurability
- Performance
- Scalability

## Table of Contents

1. [Description](#description)
2. [Installation](#installation)
3. [Usage](#usage)
   - [Basic Example](#basic-example)
   - [Advanced Usage](#advanced-usage)
4. [Features](#features)
5. [Configuration](#configuration)
6. [Testing](#testing)
7. [Development Setup](#development-setup)
8. [Proposed Implementation](#proposed-implementation)
   - [Proof of Concept (POC)](#proof-of-concept-poc)
   - [Minimum Viable Product (MVP)](#minimum-viable-product-mvp)
9. [Security Best Practices](#security-best-practices)
10. [Contribution](#contribution)
11. [License](#license)
12. [Contact](#contact)
13. [Troubleshooting](#troubleshooting)
14. [Acknowledgments](#acknowledgments)
15. [References](#references)

## Description

A lightweight, modular security framework for AI/ML models, agents, tools, and data, targeting Google ADK, Anthropic MCP, and extensible protocols that emphasizes ease of use, zero-trust security, and flexible deployment.

## Installation

To install the Aphelion Agent Security Framework, use pip:

```bash
pip install git+https://github.com/tzervas/aphelion-agent-security-framework.git@main
```

For development, we recommend using [UV](https://docs.astral.sh/uv/) for managing dependencies. See the [Development Setup](#development-setup) section for more details.

## Usage

### Basic Example

Here’s a simple example of how to use the framework:

```python
from aphelion import SecurityFramework

# Initialize the framework
framework = SecurityFramework(config_path="config.yaml")

# Authenticate a user
user = framework.authenticate(token="valid_token")

# Authorize an action
if framework.authorize(user, action="call_tool", resource="tool1"):
    result = framework.dispatch(protocol="MCP", action="call_tool", resource="tool1")
    print(result)
else:
    print("Access denied")
```

### Advanced Usage

For more advanced usage, including FastAPI integration, refer to the [Proposed Implementation](#proposed-implementation) section.

## Features

- Unified security interface for MCP and ADK
- Zero-trust authentication and authorization
- Dynamic RBAC/ABAC policies
- Data encryption and input validation
- Comprehensive logging and monitoring
- Flexible deployment options (Docker, Kubernetes, etc.)

## Configuration

The framework can be configured using a YAML file or environment variables. Example `config.yaml`:

```yaml
authentication:
  jwt_secret: "your_secret_key"
authorization:
  model_file: "rbac_model.conf"
  policy_file: "rbac_policy.csv"
logging:
  level: "INFO"
  file: "security.log"
```

For a full list of options, see the [Configuration Guide](docs/configuration.md). <!-- Assuming such a guide exists -->

## Testing

To run the tests, use:

```bash
pytest
```

Ensure development dependencies are installed. See the [Development Setup](#development-setup) section.
---

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/tzervas/aphelion-agent-security-framework.git
   ```
2. Navigate to the project directory:
   ```bash
   cd aphelion-agent-security-framework
   ```
3. Use [UV](https://docs.astral.sh/uv/) to install dependencies:
   ```bash
   uv sync
   ```
4. Configure the framework by updating `config.yaml` or setting environment variables.
5. Run the application:
   ```bash
   python main.py
   ```
   or use Docker:
   ```bash
   docker-compose up
   ```

---

## Proposed Implementation

### Proof of Concept (POC)

Demonstrates core security concepts in a simplified form.

```python
import jwt
from casbin import Enforcer
from anthropic import Anthropic  # Hypothetical MCP client
from google.adk.agents import Agent  # Hypothetical ADK client

enforcer = Enforcer("rbac_model.conf", "rbac_policy.csv")

def authenticate(token):
    return jwt.decode(token, "secret", algorithms=["HS256"])["sub"]

def authorize(subject, action, resource):
    return enforcer.enforce(subject, action, resource)

def handle_request(protocol, token, action, resource):
    subject = authenticate(token)
    if authorize(subject, action, resource):
        if protocol == "MCP":
            return Anthropic().call_tool(action, resource)
        elif protocol == "ADK":
            return Agent().call_tool(action, resource)
    raise PermissionError("Access denied")

# Test
request = {"protocol": "MCP", "token": "valid_token", "action": "call_tool", "resource": "tool1"}
result = handle_request(**request)
print(result)
```

### Minimum Viable Product (MVP)

Robust, configurable, and deployment-ready for go-to-market.

```python
from fastapi import FastAPI, HTTPException
from casbin import Enforcer
from jwt import decode
from pydantic import BaseModel
from anthropic import Anthropic
from google.adk.agents import Agent
import logging

app = FastAPI()
enforcer = Enforcer("rbac_model.conf", "rbac_policy.csv")
logging.basicConfig(level=logging.INFO)

class Request(BaseModel):
    token: str
    action: str
    resource: str

def authenticate(token):
    return decode(token, "secret", algorithms=["HS256"])["sub"]

@app.post("/mcp/call_tool")
async def mcp_call(request: Request):
    subject = authenticate(request.token)
    if enforcer.enforce(subject, request.action, request.resource):
        result = Anthropic().call_tool(request.action, request.resource)
        logging.info(f"Allowed: {subject} -> {request.action} on {request.resource}")
        return {"result": result}
    logging.warning(f"Denied: {subject} -> {request.action} on {request.resource}")
    raise HTTPException(403, "Access denied")

@app.post("/adk/call_tool")
async def adk_call(request: Request):
    subject = authenticate(request.token)
    if enforcer.enforce(subject, request.action, request.resource):
        result = Agent().call_tool(request.action, request.resource)
        logging.info(f"Allowed: {subject} -> {request.action} on {request.resource}")
        return {"result": result}
    logging.warning(f"Denied: {subject} -> {request.action} on {request.resource}")
    raise HTTPException(403, "Access denied")
```

---

## Security Best Practices

🔒
- **Zero-Trust**: Validate all requests with JWT and enforce least privilege.
- **RBAC/ABAC**: Dynamic policies via `pycasbin` for fine-grained control.
- **Encryption**: Use `cryptography` for sensitive data (configurable).
- **Input Validation**: Prevent injection attacks with strict parsing.
- **Logging**: Comprehensive audit trails with `logging` and Prometheus.
- **Dependency Management**: Minimal, vetted dependencies with regular updates.
- **Secure Defaults**: Enable encryption and strict policies by default.

---

## Contribution

Contributions are welcome! Please see the [Developer Guide](docs/developer_guide.md) and [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for more information.

## Contact

- **Author**: Tyler Zervas
- **GitHub**: [tzervas](https://github.com/tzervas)
- **X**: [@vec_wt_tech](https://x.com/vec_wt_tech)

## Troubleshooting

If you encounter issues, check the [issue tracker](https://github.com/tzervas/aphelion-agent-security-framework/issues) or contact the author.

## Acknowledgments

Special thanks to the developers of [pycasbin](https://github.com/casbin/pycasbin), [pyjwt](https://github.com/jpadilla/pyjwt), and the Loguru library for their excellent tools.

## References

- [Google Python ADK GitHub Repo](https://github.com/google/adk-python)
- [Anthropic MCP SDK](https://github.com/anthropics/anthropic-sdk-python)
- [UV Documentation](https://docs.astral.sh/uv/)

Happy Secure Agent Building!
