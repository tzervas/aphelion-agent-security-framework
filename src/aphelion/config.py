"""
Configuration management for the Aphelion Security Framework.

This module provides Pydantic-based models and utilities for loading, validating, and merging
application configuration from YAML files, environment variables, and .env files. It supports
nested configuration sections (e.g., JWT, logging), environment variable overrides, and runtime
access to a global configuration instance. Example usage and test scaffolding are included at the
bottom of the file.
"""

# src/aphelion/config.py

import os
import yaml  # noqa: F401
from pathlib import Path
from typing import Optional, Set, List, Union
from pydantic import (
    BaseModel, Field, SecretStr, ValidationError, field_validator
)
from pydantic_settings import BaseSettings, SettingsConfigDict  # noqa: F401

# --- Environment and File Paths --- 
BASE_DIR = Path(__file__).resolve().parent.parent.parent  # Project root
DEFAULT_CONFIG_FILE = BASE_DIR / "config" / "aphelion_config.yaml"

# --- Pydantic Models for Configuration Sections ---


class JWTConfigModel(BaseModel):
    """Configuration for JWT generation and validation.

    Placeholder for a more robust revocation list mechanism. This might not be directly configured
    via YAML/env for a simple set. It's more of a runtime state that might be backed by Redis/DB.
    For now, keeping it out of direct config loading, will be managed by auth module.
    """
    secret_key: SecretStr = Field(
        default_factory=lambda: SecretStr("your-default-super-secret-key-please-change")
    )
    algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=30)
    refresh_token_expire_days: int = Field(default=7)
    # revoked_tokens: Set[str] = Field(default_factory=set) # Example if needed

    @field_validator("algorithm")
    @classmethod
    def supported_algorithm(cls, value: str) -> str:
        supported = {
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
        }
        if value not in supported:
            raise ValueError(
                f"Unsupported JWT algorithm: {value}. Supported are: {supported}"
            )
        return value


class LoggingConfigModel(BaseModel):
    """Configuration for logging.

    Example: format: str = Field(default="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    """
    level: str = Field(default="INFO")
    file: Optional[Path] = Field(
        default=None
    )  # e.g., BASE_DIR / "logs" / "aphelion.log"

    @field_validator("level")
    @classmethod
    def valid_log_level(cls, value: str) -> str:
        supported_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if value.upper() not in supported_levels:
            raise ValueError(
                f"Invalid log level: {value}. Must be one of {supported_levels}"
            )
        return value.upper()


class AppConfigModel(BaseSettings):
    """Main application settings model.

    Loads settings from environment variables, .env files, and YAML files. Environment variables
    take precedence.
    """
    model_config = SettingsConfigDict(
        env_prefix="APHELION_",  # Environment variables should be prefixed (e.g., APHELION_JWT__SECRET_KEY)
        env_nested_delimiter="__",  # For nested models like JWTConfigModel
        env_file=BASE_DIR / ".env",  # Load from .env file if present
        env_file_encoding="utf-8",
        extra="ignore",  # Ignore extra fields from config files or env vars
    )

    app_name: str = Field(default="Aphelion Security Framework")
    debug_mode: bool = Field(default=False)
    jwt: JWTConfigModel = Field(default_factory=JWTConfigModel)
    logging: LoggingConfigModel = Field(default_factory=LoggingConfigModel)
    # database: DatabaseConfigModel = Field(default_factory=DatabaseConfigModel)
    # policy_engine: PolicyConfigModel = Field(default_factory=PolicyConfigModel)

    @classmethod
    def from_yaml(
        cls, yaml_file: Union[str, Path] = DEFAULT_CONFIG_FILE
    ) -> "AppConfigModel":
        """Loads configuration from a YAML file, then applies environment variables and .env files.
        """
        yaml_path = Path(yaml_file)
        file_data = {}
        if yaml_path.exists():
            try:
                with open(yaml_path, "r") as f:
                    yaml_content = yaml.safe_load(f)
                    if yaml_content:  # Ensure file is not empty
                        file_data = yaml_content
            except (yaml.YAMLError, IOError) as e:
                print(
                    f"Warning: Could not load or parse YAML config from {yaml_path}: {e}"
                )

        def deep_update(source_dict, overrides):
            """Helper for deep merging dictionaries."""
            import collections.abc
            for key, value in overrides.items():
                if isinstance(value, collections.abc.Mapping):
                    source_dict[key] = deep_update(source_dict.get(key, {}), value)
                else:
                    source_dict[key] = value
            return source_dict

        config_from_yaml_with_defaults = cls.model_validate(
            file_data if file_data else {}
        )
        config_from_env_with_defaults = cls()
        final_config_data = config_from_yaml_with_defaults.model_dump()
        env_explicitly_set_data = config_from_env_with_defaults.model_dump(
            exclude_unset=True
        )
        deep_update(final_config_data, env_explicitly_set_data)
        return cls.model_validate(final_config_data)

_app_config: Optional[AppConfigModel] = None

def get_config(config_file_path: Optional[Union[str, Path]] = None) -> AppConfigModel:
    """Retrieves the global configuration instance.

    Loads it if it hasn't been loaded yet. Allows specifying a custom config file path for the
    initial load.
    """
    global _app_config
    if _app_config is None:
        effective_config_file = (
            config_file_path or os.getenv("APHELION_CONFIG_FILE") or DEFAULT_CONFIG_FILE
        )
        try:
            _app_config = AppConfigModel.from_yaml(effective_config_file)
        except ValidationError as e:
            print(
                f"CRITICAL: Configuration validation error. Application cannot start."
            )
            print(e)
            raise
    return _app_config

# --- Example Usage (for testing or direct script execution) ---
if __name__ == "__main__":
    """Example usage and test scaffolding for configuration loading and merging."""
    with open(BASE_DIR / ".env", "w") as f:
        f.write("APHELION_DEBUG_MODE=true\n")
        f.write("APHELION_JWT__SECRET_KEY=env_secret_key_shhh\n")
        f.write("APHELION_LOGGING__LEVEL=DEBUG\n")
    dummy_yaml_path = BASE_DIR / "config" / "dummy_config.yaml"
    os.makedirs(dummy_yaml_path.parent, exist_ok=True)
    dummy_yaml_content = {
        "app_name": "Aphelion Test App from YAML",
        "debug_mode": False,  # Should be overridden by .env
        "jwt": {
            "secret_key": "yaml_secret_key_not_so_secret",  # Should be overridden by .env
            "algorithm": "HS512",
            "access_token_expire_minutes": 60,
        },
        "logging": {
            "level": "WARNING",  # Should be overridden by .env
            "file": "/tmp/aphelion_test.log",
        },
    }
    with open(dummy_yaml_path, "w") as f:
        yaml.dump(dummy_yaml_content, f)
    print(f"Base directory: {BASE_DIR}")
    print(f"Default config file path: {DEFAULT_CONFIG_FILE}")
    print(f"Dummy YAML config path: {dummy_yaml_path}")
    print("\n--- Loading config with dummy_config.yaml ---")
    try:
        config = get_config(config_file_path=dummy_yaml_path)
        print(f"App Name: {config.app_name}")  # Should be from YAML
        print(f"Debug Mode: {config.debug_mode}")  # Should be from .env (True)
        print("\nJWT Config:")
        print(
            f"  Secret Key: {config.jwt.secret_key.get_secret_value()}"
        )  # Should be from .env
        print(f"  Algorithm: {config.jwt.algorithm}")  # Should be from YAML
        print(
            f"  Access Token Expire Minutes: {config.jwt.access_token_expire_minutes}"
        )  # YAML
        print("\nLogging Config:")
        print(f"  Level: {config.logging.level}")  # Should be from .env
        print(f"  File: {config.logging.file}")  # Should be from YAML
        print(
            f"  JWT Refresh Token Expire Days (default): {config.jwt.refresh_token_expire_days}"
        )
        assert config.jwt.refresh_token_expire_days == 7  # Default from JWTConfigModel
    except ValidationError as e:
        print("Validation Error during example usage:")
        print(e)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if os.path.exists(BASE_DIR / ".env"):
            os.remove(BASE_DIR / ".env")
        if os.path.exists(dummy_yaml_path):
            os.remove(dummy_yaml_path)
        try:
            if dummy_yaml_path.parent.exists() and not any(
                dummy_yaml_path.parent.iterdir()
            ):
                os.rmdir(dummy_yaml_path.parent)
        except OSError:
            pass
        _app_config = None
        print("\n--- Example finished, cleaned up dummy files ---")
