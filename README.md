# Aphelion Agent Security Framework

A lightweight, modular security framework for AI/ML models, agents, tools, and data, targeting Google ADK, Anthropic MCP, and extensible protocols that emphasizes ease of use, zero-trust security, and flexible deployment.

## 🚀 Project Status
In active development. All components subject to change. Contributions and feedback welcome.

## 🎯 Intent
Simplify and strengthen security for AI agents, tool interactions, and data access across workflows and environments. Provide a lightweight, user-friendly solution for hobbyists, small businesses, and enterprises.

## 🛠️ Goals
- **Simplify Integration**: Templatize security controls for AI models, tools, and data, making setup intuitive.
- **Enhance Security**: Implement zero-trust authentication, RBAC/ABAC, and dynamic policies to mitigate risks.
- **Broad Applicability**: Support local sandboxes, Docker, Kubernetes, and cloud deployments.
- **Configurability**: Enable/disable features (e.g., encryption, logging) with minimal effort.
- **Performance**: Deliver lightweight, high-performance security with clear monitoring signals.
- **Scalability**: Scale from hobbyist projects to enterprise clusters without compromising usability.

## 📋 Requirements

### Functional
- **Unified Interface**: Common authentication, authorization, and logging for MCP and ADK.
- **Protocol Handlers**: Modular handlers for MCP, ADK, and future protocols.
- **Dynamic Switching**: Route requests to appropriate handlers based on protocol.
- **Zero-Trust**: Token-based authentication (JWT) and dynamic policy enforcement.
- **RBAC/ABAC**: Use `pycasbin` for role- and attribute-based access control.
- **Data Security**: Encrypt sensitive data (`cryptography`) and validate inputs.
- **Monitoring**: Real-time event logging (`logging`) and alerts.
- **Deployment**: Support Docker, Kubernetes, Helm, and local sandboxes.

### Non-Functional
- **Lightweight**: Minimize dependencies and optimize performance.
- **Idempotent**: Ensure repeatable security operations.
- **Modular**: Design reusable, extensible components.
- **Ease of Use**: Clear docs, YAML/env configs, and simple setup.
- **Maintainable**: Adhere to PEP 8 and Python best practices.
- **Scalable**: Handle small to enterprise-scale deployments.

### Constraints
- **Performance**: Avoid workflow slowdowns with efficient libraries.
- **Dependencies**: Use Python 3.12-compatible libraries (`pycasbin`, `pyjwt`, `adk-python`, `anthropic-sdk-python`).
- **Compatibility**: Focus on MCP and ADK, with extensibility plans.
- **User Skill**: Cater to hobbyists and experts, minimizing complexity.
- **Standards**: Align with zero-trust and least privilege principles.

## 🏗️ Proposed Implementation

### Proof of Concept (POC)
Demonstrates core security concepts in a simplified form.

**Components**:
- Security core: JWT authentication (`pyjwt`), RBAC authorization (`pycasbin`).
- Handlers: Basic MCP and ADK request parsing and security checks.
- Dispatcher: Routes requests based on protocol identifier.

**Functionality**:
- Authenticate agent/user with JWT.
- Authorize tool calls based on RBAC policies.
- Log events to console/file.

**Environment**: Local Python script or Docker container.

**Success Criteria**:
- Processes MCP/ADK requests.
- Consistently allows/denies based on policies.
- Logs events for verification.

**Example**:
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

**Components**:
- **Security Core**: Configurable JWT authentication, `pycasbin` authorization, and `logging`.
- **Handlers**: Full MCP/ADK handlers with error handling and token verification.
- **Dispatcher**: FastAPI-based routing (`/mcp/call_tool`, `/adk/call_tool`).

**Features**:
- Zero-trust with dynamic RBAC/ABAC.
- OAuth2 support (`auth0-python`).
- Configurable data encryption (`cryptography`).
- Comprehensive logging with Prometheus integration.
- YAML/env configuration (`pydantic`).

**Deployment**:
- Docker container with Dockerfile.
- Kubernetes manifests and Helm charts.
- Docker Compose for local sandboxing.

**Documentation**:
- README with setup, examples, and configs.
- OpenAPI spec via FastAPI.

**Success Criteria**:
- Integrates with real MCP/ADK deployments.
- Handles 100+ concurrent requests.
- Supports human/AI users and MCP/ADK protocols.
- Installs in <5 minutes.

**Example**:
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

**Dockerfile**:
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

## 🔒 Security Best Practices
- **Zero-Trust**: Validate all requests with JWT and enforce least privilege.
- **RBAC/ABAC**: Dynamic policies via `pycasbin` for fine-grained control.
- **Encryption**: Use `cryptography` for sensitive data (configurable).
- **Input Validation**: Prevent injection attacks with strict parsing.
- **Logging**: Comprehensive audit trails with `logging` and Prometheus.
- **Dependency Management**: Minimal, vetted dependencies with regular updates.
- **Secure Defaults**: Enable encryption and strict policies by default.

## 📦 Installation
```bash
pip install git+https://github.com/tzervas/aphelion-agent-security-framework.git@main
```

## 🛠️ Development Setup
1. Clone: `git clone https://github.com/tzervas/aphelion-agent-security-framework.git`
2. Install: `pip install -r requirements.txt`
3. Configure: Update `config.yaml` or env vars.
4. Run: `python main.py` or `docker-compose up`.

## 🤝 Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for bug reports, feature requests, and code contributions.

## 📄 License
Apache 2.0 - See [LICENSE](LICENSE) for details.

## 📚 References
- [Google ADK](https://github.com/google/adk-python)
- [Anthropic MCP SDK](https://github.com/anthropics/anthropic-sdk-python)

Happy Secure Agent Building!