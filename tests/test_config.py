# tests/test_config.py

import os
import yaml
import pytest
from pathlib import Path
from pydantic import SecretStr, ValidationError
from unittest.mock import patch

from aphelion.config import AppConfigModel, JWTConfigModel, LoggingConfigModel, get_config, DEFAULT_CONFIG_FILE

BASE_DIR_FOR_TESTS = Path(__file__).resolve().parent.parent # Project root for test context

# Store original env vars to restore them after tests
ORIGINAL_ENV_VARS = {}

def setup_module(module):
    """Save original environment variables that might be modified by tests."""
    vars_to_save = [
        "APHELION_APP_NAME",
        "APHELION_DEBUG_MODE",
        "APHELION_JWT__SECRET_KEY",
        "APHELION_JWT__ALGORITHM",
        "APHELION_JWT__ACCESS_TOKEN_EXPIRE_MINUTES",
        "APHELION_LOGGING__LEVEL",
        "APHELION_CONFIG_FILE" # If used to redirect config loading globally
    ]
    for var_name in vars_to_save:
        if var_name in os.environ:
            ORIGINAL_ENV_VARS[var_name] = os.environ[var_name]
        # Ensure env vars that will be set by tests are cleared before tests run,
        # or use monkeypatch fixture from pytest.
        if os.environ.get(var_name):
            del os.environ[var_name]


def teardown_module(module):
    """Restore original environment variables."""
    for var_name, value in ORIGINAL_ENV_VARS.items():
        os.environ[var_name] = value
    # Clean up any env vars set by tests that weren't originally there
    test_set_vars = [
        "APHELION_APP_NAME", "APHELION_DEBUG_MODE", "APHELION_JWT__SECRET_KEY",
        "APHELION_JWT__ALGORITHM", "APHELION_JWT__ACCESS_TOKEN_EXPIRE_MINUTES",
        "APHELION_LOGGING__LEVEL", "APHELION_CONFIG_FILE"
    ]
    for var_name in test_set_vars:
        if var_name not in ORIGINAL_ENV_VARS and var_name in os.environ:
            del os.environ[var_name]


@pytest.fixture(autouse=True)
def reset_global_config_and_env(monkeypatch):
    """
    Resets the global _app_config in aphelion.config to None before each test,
    and cleans up specific environment variables set by tests.
    """
    # Reset the internal _app_config variable in the config module
    # This forces get_config() to reload in each test if called.
    with patch('aphelion.config._app_config', None):
        # Clean specific env vars using monkeypatch for safety
        env_vars_to_clear = [
            "APHELION_APP_NAME", "APHELION_DEBUG_MODE", "APHELION_JWT__SECRET_KEY",
            "APHELION_JWT__ALGORITHM", "APHELION_JWT__ACCESS_TOKEN_EXPIRE_MINUTES",
            "APHELION_LOGGING__LEVEL", "APHELION_CONFIG_FILE"
        ]
        for var in env_vars_to_clear:
            monkeypatch.delenv(var, raising=False)
        yield


@pytest.fixture
def dummy_config_yaml_file(tmp_path: Path) -> Path:
    """Creates a temporary YAML config file for testing."""
    config_content = {
        "app_name": "Test App YAML",
        "debug_mode": True,
        "jwt": {
            "secret_key": "yaml_secret",
            "algorithm": "HS512",
            "access_token_expire_minutes": 60,
        },
        "logging": {
            "level": "DEBUG",
            "file": "/tmp/test_app.log"
        }
    }
    config_dir = tmp_path / "config"
    config_dir.mkdir(exist_ok=True)
    yaml_file = config_dir / "test_config.yaml"
    with open(yaml_file, 'w') as f:
        yaml.dump(config_content, f)
    return yaml_file

def test_load_defaults_no_file_no_env():
    """Test that default values are loaded if no config file or env vars are set."""
    # Ensure no config file is pointed to by env var for this test
    if "APHELION_CONFIG_FILE" in os.environ:
        del os.environ["APHELION_CONFIG_FILE"]

    # Patch DEFAULT_CONFIG_FILE to point to a non-existent file for this test
    with patch('aphelion.config.DEFAULT_CONFIG_FILE', BASE_DIR_FOR_TESTS / "non_existent_config.yaml"):
        config = get_config()

    assert config.app_name == "Aphelion Security Framework" # Default
    assert config.debug_mode is False # Default
    assert config.jwt.secret_key.get_secret_value() == "your-default-super-secret-key-please-change"
    assert config.jwt.algorithm == "HS256"
    assert config.jwt.access_token_expire_minutes == 30
    assert config.logging.level == "INFO"
    assert config.logging.file is None

def test_load_from_yaml_file(dummy_config_yaml_file: Path):
    """Test loading configuration purely from a YAML file."""
    config = get_config(config_file_path=dummy_config_yaml_file)

    assert config.app_name == "Test App YAML"
    assert config.debug_mode is True
    assert config.jwt.secret_key.get_secret_value() == "yaml_secret"
    assert config.jwt.algorithm == "HS512"
    assert config.jwt.access_token_expire_minutes == 60
    assert config.logging.level == "DEBUG"
    assert str(config.logging.file) == "/tmp/test_app.log" # Path objects comparison

def test_load_from_env_vars_override_yaml(dummy_config_yaml_file: Path, monkeypatch):
    """Test that environment variables override YAML file settings."""
    monkeypatch.setenv("APHELION_APP_NAME", "Test App ENV")
    monkeypatch.setenv("APHELION_DEBUG_MODE", "false") # Note: pydantic-settings handles bool conversion
    monkeypatch.setenv("APHELION_JWT__SECRET_KEY", "env_secret")
    monkeypatch.setenv("APHELION_JWT__ALGORITHM", "RS256")
    monkeypatch.setenv("APHELION_LOGGING__LEVEL", "ERROR")

    config = get_config(config_file_path=dummy_config_yaml_file)

    assert config.app_name == "Test App ENV"
    assert config.debug_mode is False # Pydantic converts "false"
    assert config.jwt.secret_key.get_secret_value() == "env_secret"
    assert config.jwt.algorithm == "RS256"
    assert config.jwt.access_token_expire_minutes == 60 # From YAML (not overridden by env)
    assert config.logging.level == "ERROR"
    assert str(config.logging.file) == "/tmp/test_app.log" # From YAML

def test_load_from_env_vars_only(monkeypatch):
    """Test loading configuration purely from environment variables (no YAML file)."""
    monkeypatch.setenv("APHELION_APP_NAME", "ENV App Only")
    monkeypatch.setenv("APHELION_DEBUG_MODE", "true")
    monkeypatch.setenv("APHELION_JWT__SECRET_KEY", "env_only_secret")
    monkeypatch.setenv("APHELION_JWT__ALGORITHM", "ES256")
    monkeypatch.setenv("APHELION_JWT__ACCESS_TOKEN_EXPIRE_MINUTES", "15")
    monkeypatch.setenv("APHELION_LOGGING__LEVEL", "CRITICAL")

    # Patch DEFAULT_CONFIG_FILE to a non-existent one to ensure no YAML is loaded
    with patch('aphelion.config.DEFAULT_CONFIG_FILE', BASE_DIR_FOR_TESTS / "no_such_config.yaml"):
        config = get_config()

    assert config.app_name == "ENV App Only"
    assert config.debug_mode is True
    assert config.jwt.secret_key.get_secret_value() == "env_only_secret"
    assert config.jwt.algorithm == "ES256"
    assert config.jwt.access_token_expire_minutes == 15
    assert config.logging.level == "CRITICAL"
    assert config.logging.file is None # Default, as not set by env

def test_jwt_config_invalid_algorithm_in_yaml(tmp_path: Path):
    """Test validation error for unsupported JWT algorithm in YAML."""
    config_content = {"jwt": {"algorithm": "INVALID_ALGO"}}
    yaml_file = tmp_path / "invalid_algo.yaml"
    with open(yaml_file, 'w') as f:
        yaml.dump(config_content, f)

    with pytest.raises(ValidationError) as excinfo:
        get_config(config_file_path=yaml_file)
    assert "Unsupported JWT algorithm: INVALID_ALGO" in str(excinfo.value)

def test_logging_config_invalid_level_in_env(monkeypatch):
    """Test validation error for invalid logging level from environment."""
    monkeypatch.setenv("APHELION_LOGGING__LEVEL", "SUPER_VERBOSE")

    with patch('aphelion.config.DEFAULT_CONFIG_FILE', BASE_DIR_FOR_TESTS / "no_such_config.yaml"):
        with pytest.raises(ValidationError) as excinfo:
            get_config()
    assert "Invalid log level: SUPER_VERBOSE" in str(excinfo.value)

def test_secret_str_hides_secret_in_repr():
    """Test that SecretStr correctly hides the secret key in representations."""
    config = AppConfigModel(jwt=JWTConfigModel(secret_key="my_very_secret_key")) # type: ignore
    assert "my_very_secret_key" not in repr(config.jwt.secret_key)
    assert "**********" in repr(config.jwt.secret_key)
    assert config.jwt.secret_key.get_secret_value() == "my_very_secret_key"

def test_config_file_env_variable_precedence(tmp_path: Path, monkeypatch):
    """Test APHELION_CONFIG_FILE environment variable overrides default path."""
    default_yaml_content = {"app_name": "Default YAML Name"}
    default_config_dir = tmp_path / "default_config_dir"
    default_config_dir.mkdir()
    default_yaml_file = default_config_dir / "aphelion_config.yaml" # Simulates DEFAULT_CONFIG_FILE
    with open(default_yaml_file, 'w') as f:
        yaml.dump(default_yaml_content, f)

    custom_yaml_content = {"app_name": "Custom YAML Name via ENV Var"}
    custom_yaml_file = tmp_path / "custom_path.yaml"
    with open(custom_yaml_file, 'w') as f:
        yaml.dump(custom_yaml_content, f)

    # Patch the DEFAULT_CONFIG_FILE constant in the module to point to our temp default
    # This simulates the actual default file being present.
    with patch('aphelion.config.DEFAULT_CONFIG_FILE', default_yaml_file):
        # 1. Test without APHELION_CONFIG_FILE env var (should load from patched DEFAULT_CONFIG_FILE)
        config_default = get_config()
        assert config_default.app_name == "Default YAML Name"

        # 2. Test with APHELION_CONFIG_FILE env var
        # Must reset _app_config for get_config to re-evaluate path
        with patch('aphelion.config._app_config', None):
            monkeypatch.setenv("APHELION_CONFIG_FILE", str(custom_yaml_file))
            config_custom = get_config()
            assert config_custom.app_name == "Custom YAML Name via ENV Var"

        # 3. Test with get_config(config_file_path=...) taking highest precedence
        even_more_custom_yaml_file = tmp_path / "even_more_custom.yaml"
        with open(even_more_custom_yaml_file, 'w') as f:
            yaml.dump({"app_name": "Explicit Path Parameter Name"}, f)

        with patch('aphelion.config._app_config', None):
            # APHELION_CONFIG_FILE is still set to custom_yaml_file
            config_explicit_param = get_config(config_file_path=even_more_custom_yaml_file)
            assert config_explicit_param.app_name == "Explicit Path Parameter Name"

# Cleanup dummy .env file if created by config.py's __main__ during test collection
# This is a bit of a hack; ideally, __main__ blocks shouldn't have side effects
# or tests should fully isolate file system operations.
if os.path.exists(BASE_DIR_FOR_TESTS / ".env"):
    try:
        os.remove(BASE_DIR_FOR_TESTS / ".env")
    except OSError:
        pass # Ignore if it can't be removed (e.g. permissions, or already gone)
