# Aphelion Agent Security Framework Developer Guide

## Introduction

The Aphelion Agent Security Framework is a lightweight, modular security framework designed to simplify and strengthen security for AI agents, tool interactions, and data access across workflows and environments. It targets Google ADK, Anthropic MCP, and extensible protocols, emphasizing ease of use, zero-trust security, and flexible deployment. This guide helps developers set up their environment, understand the project structure, and contribute effectively.

## Setting Up the Development Environment

### Prerequisites

- **Python**: 3.11 or higher
- **UV**: For dependency management (recommended over pip for performance)
- **Git**: For version control

### Cloning the Repository

Clone the repository from GitHub:

```bash
git clone https://github.com/tzervas/aphelion-agent-security-framework.git
```

### Installing Dependencies

Navigate to the project directory and install dependencies using UV:

```bash
cd aphelion-agent-security-framework
uv sync
```

Alternatively, use pip (less recommended):

```bash
pip install -r requirements.txt
```

### Configuring the Environment

- Update the `config.yaml` file in the `config/` directory with your settings (e.g., JWT secrets, policy files).
- Alternatively, set environment variables to override `config.yaml` values. Example:
  ```bash
  export JWT_SECRET="your_secret_key"
  ```

Refer to the [Configuration Guide](docs/configuration.md) for a full list of options.

## Project Structure

### Directory Overview

- **`src/`**: Contains the source code for the framework.
- **`tests/`**: Test cases for unit, integration, and security testing.
- **`docs/`**: Documentation files, including this guide.
- **`config/`**: Configuration files (e.g., `config.yaml`, RBAC policy files).

### Key Modules

- **`aphelion.py`**: Core security framework class, managing authentication, authorization, and dispatching.
- **`auth.py`**: Handles authentication logic (e.g., JWT validation).
- **`policies.py`**: Implements policy enforcement using PyCasbin for RBAC/ABAC.

## Development Workflow

### Branching Strategy

- **Feature Branches**: Create branches for new features (e.g., `feature/new-auth-method`).
- **Bugfix Branches**: Create branches for fixes (e.g., `bugfix/auth-error`).
- Target the `main` branch for pull requests.

### Coding Standards

- Adhere to **PEP8** for Python code style.
- Use **type hints** to improve code readability and maintainability.
- Follow **security best practices**:
  - Validate all inputs to prevent injection attacks.
  - Apply the principle of least privilege in policy design.
  - Avoid hardcoding sensitive data (use configuration instead).

### Testing Requirements

- Write **unit tests** for all new features and bug fixes.
- Use **pytest** to run tests:
  ```bash
  pytest
  ```
- Aim for high test coverage, including security-specific tests (e.g., fuzzing with Hypothesis).

### Documentation Standards

- Use **Google-style docstrings** for all public functions and classes.
- Update relevant documentation (e.g., this guide, API docs) when making changes.

## Building and Running the Project

### Building

No separate build step is required for Python. Ensure dependencies are installed.

### Running Locally

Run the application:

```bash
python main.py
```

Alternatively, use Docker for a containerized setup:

```bash
docker-compose up
```

### Running Tests

Execute the test suite:

```bash
pytest
```

## Debugging and Troubleshooting

### Common Issues

- **Dependency Conflicts**: Use UV to resolve (`uv sync`).
- **Configuration Errors**: Verify `config.yaml` syntax and environment variables.
- **Permission Denied**: Check RBAC/ABAC policies in `rbac_model.conf` and `rbac_policy.csv`.

### Debugging Tools

- Use **`pdb`** for interactive debugging:
  ```bash
  python -m pdb main.py
  ```
- Check logs in `security.log` (configured via `config.yaml`).

## Advanced Topics

### Performance Optimization

- Profile with **`cProfile`** to identify bottlenecks:
  ```bash
  python -m cProfile main.py
  ```
- Optimize critical paths (e.g., authentication, encryption) using async patterns and caching.

### Security Considerations

- Implement **zero-trust principles**: Continuously verify all entities.
- Use **secure defaults**: Enable encryption and strict policies out of the box.
- Leverage **PyCasbin** for dynamic RBAC/ABAC enforcement.

### Extending the Framework

- Add new **protocol handlers** (e.g., for additional AI frameworks) by extending `AphelionSecurityManager`.
- Implement **custom policies** in `policies.py` to support specific use cases.