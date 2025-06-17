# Contributing to Aphelion Agent Security Framework

## Introduction

We welcome contributions to the Aphelion Agent Security Framework! Whether you're fixing bugs, adding features, or improving documentation, your efforts help make this lightweight, modular security framework better for everyone. This guide outlines how to contribute effectively.

## How to Contribute

### Reporting Issues

- Use the [GitHub issue tracker](https://github.com/tzervas/aphelion-agent-security-framework/issues).
- Provide a detailed description, including steps to reproduce and expected vs. actual behavior.

### Suggesting Enhancements

- Open an issue with the "enhancement" label.
- Describe the proposed feature, its benefits, and potential implementation details.

### Submitting Pull Requests

- Follow the pull request process outlined below to submit code changes.

## Coding Standards

### Python Guidelines

- Follow **PEP8** for consistent code style.
- Use **meaningful variable names** and keep code clear and concise.
- Leverage **type hints** for better maintainability.

### Security Best Practices

- **Validate all inputs** to prevent injection attacks.
- Apply **least privilege principles** in policy enforcement.
- Avoid hardcoding sensitive information—use `config.yaml` or environment variables.

### Documentation Requirements

- Document all public functions and classes with **Google-style docstrings**.
- Update relevant guides (e.g., Developer Guide, API docs) for significant changes.

## Testing Requirements

### Types of Tests

- **Unit Tests**: Cover individual components (e.g., authentication logic).
- **Integration Tests**: Validate interactions between components.
- **Security Tests**: Test for vulnerabilities (e.g., injection, privilege escalation).

### Writing Tests

- Use **pytest** for test implementation.
- Aim for high test coverage using tools like `coverage.py`.
- Include edge cases and security-specific scenarios.

### Running Tests

Run the full test suite:

```bash
pytest
```

## Pull Request Process

1. **Fork the Repository**
   - Create a personal fork on GitHub.

2. **Create a Branch**
   - Use a descriptive name (e.g., `feature/new-auth-method`, `bugfix/policy-bug`).

3. **Commit Changes**
   - Write clear, concise commit messages (e.g., "Add OAuth 2.1 support for MCP").
   - Reference relevant issues (e.g., "Fixes #123").

4. **Open a Pull Request**
   - Target the `main` branch.
   - Provide a detailed description of your changes and their purpose.
   - Link to related issues (e.g., "Resolves #123").

5. **Review Process**
   - Address feedback from maintainers.
   - Ensure all automated checks (e.g., tests, linting) pass.

## Code of Conduct

### Community Standards

- Be **respectful** and **courteous** in all interactions.
- Follow the project's [Code of Conduct](CODE_OF_CONDUCT.md) to maintain a positive community.
