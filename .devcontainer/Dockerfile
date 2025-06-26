# Using a Debian-based image for broad compatibility
FROM mcr.microsoft.com/devcontainers/python:0-3.12-bullseye

# Set environment variables to prevent interactive prompts during installation
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    # Poetry specific (though we're using uv, good to be aware for general python dev)
    # POETRY_HOME="/opt/poetry" \
    # POETRY_VERSION="1.7.1" \
    # PATH="$POETRY_HOME/bin:$PATH" \
    # Uv specific install location if needed, but we'll use pipx or direct curl
    UV_HOME="/opt/uv" \
    PATH="$UV_HOME/bin:$PATH"

# Install system dependencies that might be needed by Python packages
# Example: libffi-dev for cffi, build-essential for compiling some packages
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    curl \
    git \
    # Add any other system dependencies here, e.g., libpq-dev for psycopg2
    # build-essential libssl-dev zlib1g-dev libbz2-dev \
    # libreadline-dev libsqlite3-dev llvm libncurses5-dev libncursesw5-dev \
    # xz-utils tk-dev libffi-dev liblzma-dev python3-openssl
    && apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/*

# Install uv using the recommended installer
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Switch to a non-root user for security
# VS Code dev containers will often create a 'vscode' user by default if not specified.
# If you need a specific UID/GID, you can create the user explicitly.
# For now, we'll rely on the user created by the base image or VS Code.
# The "remoteUser": "vscode" in devcontainer.json will handle this.

# Copy project files
# This will be done by the devcontainer build process, but good to note if building manually
# COPY . /workspace
# WORKDIR /workspace

# The postCreateCommand in devcontainer.json will handle venv creation and dependency installation.
# Example: "postCreateCommand": "uv venv .venv --python 3.12 && source .venv/bin/activate && uv sync --all-extras",

# Expose ports if necessary (though devcontainer.json's forwardPorts is usually sufficient)
# EXPOSE 8000

# Default command (can be overridden)
# CMD ["sleep", "infinity"]
# For a Python app, it might be something like:
# CMD ["uvicorn", "src.aphelion.main:app", "--host", "0.0.0.0", "--port", "8000"]
# But for a dev container, usually no CMD is needed as it's for interactive development.

# Final check for uv installation and PATH
RUN echo "uv is installed at: $(command -v uv)" && uv --version
