# tests/authz/test_casbin_enforcer.py

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
import casbin # Reverted to casbin

from aphelion.authz.casbin_enforcer import (
    init_enforcer,
    get_enforcer,
    enforce,
    PolicyError,
    NotAuthorizedError, # Will test this if enforce is modified to raise it
    DEFAULT_MODEL_PATH,
    DEFAULT_POLICY_PATH,
    _enforcer as global_enforcer_instance # For resetting
)

# --- Test Fixtures ---

@pytest.fixture(autouse=True)
def reset_target_module_enforcer():
    """
    Ensures the _enforcer in the aphelion.authz.casbin_enforcer module
    is reset to None before each test and restored afterwards.
    """
    import aphelion.authz.casbin_enforcer as ce_module
    original_module_enforcer = ce_module._enforcer
    ce_module._enforcer = None
    yield
    ce_module._enforcer = original_module_enforcer

@pytest.fixture
def default_model_file() -> Path:
    # Ensure this points to the actual default model file relative to project root
    project_root = Path(__file__).resolve().parent.parent.parent
    model_path = project_root / "config" / "rbac_model.conf"
    if not model_path.exists():
        pytest.fail(f"Default model file not found for tests: {model_path}")
    return model_path

@pytest.fixture
def default_policy_file() -> Path:
    project_root = Path(__file__).resolve().parent.parent.parent
    policy_path = project_root / "config" / "rbac_policy.csv"
    if not policy_path.exists():
        pytest.fail(f"Default policy file not found for tests: {policy_path}")
    return policy_path

@pytest.fixture
def temp_model_file(tmp_path: Path) -> Path:
    model_content = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
    """
    file_path = tmp_path / "test_model.conf"
    file_path.write_text(model_content)
    return file_path

@pytest.fixture
def temp_policy_file(tmp_path: Path) -> Path:
    policy_content = """
p, test_admin, resource1, read
p, test_admin, resource1, write
p, test_user, resource1, read
g, alice_test, test_admin
    """
    file_path = tmp_path / "test_policy.csv"
    file_path.write_text(policy_content)
    return file_path

# --- Initialization Tests ---

def test_init_enforcer_default_paths(default_model_file, default_policy_file):
    """Test enforcer initialization with default model and policy files."""
    # Patch the constants in casbin_enforcer to ensure they point to our test-verified paths
    # This is important if the test execution environment base path differs from module's expectation.
    with patch('aphelion.authz.casbin_enforcer.DEFAULT_MODEL_PATH', default_model_file):
        with patch('aphelion.authz.casbin_enforcer.DEFAULT_POLICY_PATH', default_policy_file):
            enforcer = init_enforcer()
            assert isinstance(enforcer, casbin.Enforcer) # Reverted to casbin.Enforcer
            assert enforcer is get_enforcer() # Should return the same instance

def test_init_enforcer_custom_paths(temp_model_file: Path, temp_policy_file: Path):
    """Test enforcer initialization with custom model and policy files."""
    enforcer = init_enforcer(model_path=temp_model_file, policy_adapter=temp_policy_file)
    assert isinstance(enforcer, casbin.Enforcer) # Reverted to casbin.Enforcer
    # Check if it loaded the custom policy
    assert enforcer.enforce("test_admin", "resource1", "read") is True
    assert enforcer.enforce("alice_test", "resource1", "write") is True # via role
    assert enforcer.enforce("test_user", "resource1", "write") is False

def test_init_enforcer_missing_model_file(tmp_path: Path, default_policy_file):
    """Test PolicyError when model file is missing."""
    missing_model_path = tmp_path / "non_existent_model.conf"
    with patch('aphelion.authz.casbin_enforcer.DEFAULT_POLICY_PATH', default_policy_file):
      with pytest.raises(PolicyError, match="Casbin model file not found"):
          init_enforcer(model_path=missing_model_path)

def test_init_enforcer_missing_policy_file(default_model_file, tmp_path: Path):
    """Test PolicyError when policy file is missing."""
    missing_policy_path = tmp_path / "non_existent_policy.csv"
    with patch('aphelion.authz.casbin_enforcer.DEFAULT_MODEL_PATH', default_model_file):
      # Casbin's FileAdapter itself raises "invalid file path" if it's missing on load attempt.
      # Our wrapper catches this and re-raises.
      with pytest.raises(PolicyError, match="Failed to initialize Casbin enforcer: invalid file path"):
          init_enforcer(policy_adapter=missing_policy_path)

def test_get_enforcer_initializes_if_none(default_model_file, default_policy_file):
    """Test get_enforcer() initializes with defaults if not already done."""
    import aphelion.authz.casbin_enforcer as ce_module # Import for direct access

    # Pre-condition: The fixture should have set the target module's _enforcer to None
    assert ce_module._enforcer is None

    with patch('aphelion.authz.casbin_enforcer.DEFAULT_MODEL_PATH', default_model_file):
        with patch('aphelion.authz.casbin_enforcer.DEFAULT_POLICY_PATH', default_policy_file):
            enforcer = get_enforcer()
            assert isinstance(enforcer, casbin.Enforcer) # Reverted to casbin.Enforcer
            # Post-condition: The target module's _enforcer should now be the initialized enforcer
            assert ce_module._enforcer is not None
            assert ce_module._enforcer is enforcer

def test_init_enforcer_returns_same_instance_if_paths_match(default_model_file, default_policy_file):
    # This test relies on the global _enforcer state, so direct checks are also good.
    import aphelion.authz.casbin_enforcer as ce_module
    with patch('aphelion.authz.casbin_enforcer.DEFAULT_MODEL_PATH', default_model_file):
        with patch('aphelion.authz.casbin_enforcer.DEFAULT_POLICY_PATH', default_policy_file):
            e1 = init_enforcer()
            assert ce_module._enforcer is e1 # Global is set to e1
            e2 = init_enforcer() # Calling again with same implicit paths
            assert e1 is e2      # Should return the same instance from global
            assert ce_module._enforcer is e1 # Global should remain e1

def test_init_enforcer_reinitializes_if_model_path_differs(default_model_file, default_policy_file, temp_model_file):
    import aphelion.authz.casbin_enforcer as ce_module
    with patch('aphelion.authz.casbin_enforcer.DEFAULT_MODEL_PATH', default_model_file):
        with patch('aphelion.authz.casbin_enforcer.DEFAULT_POLICY_PATH', default_policy_file):
            e1 = init_enforcer()
            assert ce_module._enforcer is e1 # Global is e1
            # Use the same temp_policy_file to isolate model change, or default_policy_file
            e2 = init_enforcer(model_path=temp_model_file, policy_adapter=default_policy_file)
            assert e1 is not e2
            assert ce_module._enforcer is e2 # Global should now be e2


# --- Authorization (enforce) Tests ---
# These tests use the default model and policy files.
@pytest.mark.parametrize("subject, obj, action, expected_auth", [
    # Based on default rbac_policy.csv
    ("alice", "data_resource_1", "read", True),      # Admin alice can read data1
    ("alice", "data_resource_1", "write", True),     # Admin alice can write data1
    ("alice", "tool_alpha", "execute", True),        # Admin alice can execute tool_alpha
    ("bob", "data_resource_1", "read", True),        # Editor bob can read data1
    ("bob", "data_resource_1", "write", True),       # Editor bob can write data1
    ("bob", "tool_beta", "execute", True),           # Editor bob can execute tool_beta
    ("bob", "tool_alpha", "execute", False),         # Editor bob CANNOT execute tool_alpha
    ("cathy", "data_resource_1", "read", True),      # Viewer cathy can read data1
    ("cathy", "data_resource_1", "write", False),    # Viewer cathy CANNOT write data1
    ("cathy", "tool_alpha", "execute", False),       # Viewer cathy CANNOT execute tool_alpha
    ("nobody", "data_resource_1", "read", False),    # Non-existent user
    ("alice", "non_existent_obj", "read", False),   # Admin on non-existent object
    ("alice", "data_resource_1", "fly", False),     # Admin with non-existent action
])
def test_enforce_default_policies(subject, obj, action, expected_auth, default_model_file, default_policy_file):
    # Ensure enforcer is initialized with default files for these tests
    with patch('aphelion.authz.casbin_enforcer.DEFAULT_MODEL_PATH', default_model_file):
        with patch('aphelion.authz.casbin_enforcer.DEFAULT_POLICY_PATH', default_policy_file):
            init_enforcer()
            assert enforce(subject, obj, action) is expected_auth

def test_enforce_uninitialized_raises_policy_error_via_get_enforcer(tmp_path):
    """Test that enforce calls get_enforcer which might raise PolicyError if init fails."""
    global global_enforcer_instance
    global_enforcer_instance = None # Ensure it's not initialized

    # Make default model path invalid to cause init failure
    with patch('aphelion.authz.casbin_enforcer.DEFAULT_MODEL_PATH', tmp_path / "bad_model.conf"):
        with pytest.raises(PolicyError):
            enforce("sub", "obj", "act")

# Future: If `enforce` is changed to raise NotAuthorizedError:
# def test_enforce_raises_not_authorized_error(default_model_file, default_policy_file):
#     with patch('aphelion.authz.casbin_enforcer.DEFAULT_MODEL_PATH', default_model_file):
#         with patch('aphelion.authz.casbin_enforcer.DEFAULT_POLICY_PATH', default_policy_file):
#             init_enforcer()
#             with pytest.raises(NotAuthorizedError):
#                 # Call enforce here with a case known to be false, if it's modified to raise
#                 # For now, it returns False, so this test is commented out.
                      # enforce("cathy", "data_resource_1", "write", _raise=True)
                      # assuming an imaginary _raise flag or separate function

# --- Test Policy Management (Illustrative - if functions were added) ---
# These would require functions like add_policy, remove_policy in casbin_enforcer.py

# def test_add_policy_dynamically(temp_model_file, temp_policy_file):
#     enforcer = init_enforcer(model_path=temp_model_file, policy_adapter=temp_policy_file)
#     assert enforcer.enforce("new_user", "new_resource", "new_action") is False
#
#     # Assume add_policy_rule(sub, obj, act) exists in casbin_enforcer.py
#     # result = add_policy_rule("new_user", "new_resource", "new_action")
#     # assert result is True
#     # assert enforcer.enforce("new_user", "new_resource", "new_action") is True

#     # This would also require enforcer.save_policy() if using FileAdapter and wanting persistence
#     # or if using an auto-saving adapter.


# --- Test Role Management (Illustrative) ---
# def test_role_assignment_and_check(temp_model_file, temp_policy_file):
#     enforcer = init_enforcer(model_path=temp_model_file, policy_adapter=temp_policy_file)
#     # Assume policy file has: p, editor_role, data, read
#     # Assume add_role_for_user(user, role) exists
#     # add_role_for_user("dave", "editor_role")
#     # assert enforcer.enforce("dave", "data", "read") is True
# pass # Removed to avoid being the last line if other tests are added below

# --- Policy Management Function Tests ---

def test_add_and_remove_policy_rule(temp_model_file, temp_policy_file):
    """Test adding and removing a 'p' policy rule."""
    enforcer = init_enforcer(model_path=temp_model_file, policy_adapter=temp_policy_file)
    from aphelion.authz.casbin_enforcer import add_policy_rule, remove_policy_rule, enforce as aphelion_enforce

    sub, obj, act = "new_user", "new_resource", "new_action"

    assert aphelion_enforce(sub, obj, act) is False # Should not exist initially

    # Add policy
    assert add_policy_rule(sub, obj, act) is True
    assert aphelion_enforce(sub, obj, act) is True

    # Try adding again (should return False as it already exists)
    assert add_policy_rule(sub, obj, act) is False

    # Remove policy
    assert remove_policy_rule(sub, obj, act) is True
    assert aphelion_enforce(sub, obj, act) is False

    # Try removing again (should return False as it's gone)
    assert remove_policy_rule(sub, obj, act) is False


def test_add_and_remove_grouping_policy_rule(temp_model_file, temp_policy_file):
    """Test adding and removing a 'g' (grouping/role) policy rule."""
    enforcer = init_enforcer(model_path=temp_model_file, policy_adapter=temp_policy_file)
    from aphelion.authz.casbin_enforcer import (
        add_grouping_policy_rule, remove_grouping_policy_rule,
        add_policy_rule, enforce as aphelion_enforce
    )

    user, role = "dave_user", "temp_editor_role"
    obj, act = "documentX", "edit"

    # Add a policy for the role first
    add_policy_rule(role, obj, act)
    assert aphelion_enforce(user, obj, act) is False # Dave is not yet in the role

    # Add grouping policy (assign user to role)
    assert add_grouping_policy_rule(user, role) is True
    assert aphelion_enforce(user, obj, act) is True # Dave should now have permission

    # Try adding again
    assert add_grouping_policy_rule(user, role) is False

    # Remove grouping policy
    assert remove_grouping_policy_rule(user, role) is True
    assert aphelion_enforce(user, obj, act) is False # Dave should lose permission

    # Try removing again
    assert remove_grouping_policy_rule(user, role) is False


def test_get_all_policy_rules(default_model_file, default_policy_file):
    """Test retrieving all 'p' policies."""
    with patch('aphelion.authz.casbin_enforcer.DEFAULT_MODEL_PATH', default_model_file):
        with patch('aphelion.authz.casbin_enforcer.DEFAULT_POLICY_PATH', default_policy_file):
            init_enforcer()
            from aphelion.authz.casbin_enforcer import get_all_policy_rules
            rules = get_all_policy_rules()
            assert isinstance(rules, list)
            # Based on default_policy.csv, check a few expected rules
            # Note: order might not be guaranteed, so check for presence
            expected_admin_read = ["admin", "data_resource_1", "read"]
            expected_viewer_read = ["viewer", "data_resource_1", "read"]
            assert any(rule == expected_admin_read for rule in rules)
            assert any(rule == expected_viewer_read for rule in rules)
            assert len(rules) >= 7 # Count 'p' rules in default file

def test_get_all_grouping_policy_rules(default_model_file, default_policy_file):
    """Test retrieving all 'g' policies."""
    with patch('aphelion.authz.casbin_enforcer.DEFAULT_MODEL_PATH', default_model_file):
        with patch('aphelion.authz.casbin_enforcer.DEFAULT_POLICY_PATH', default_policy_file):
            init_enforcer()
            from aphelion.authz.casbin_enforcer import get_all_grouping_policy_rules
            grouping_rules = get_all_grouping_policy_rules()
            assert isinstance(grouping_rules, list)
            expected_alice_admin = ["alice", "admin"]
            assert any(rule == expected_alice_admin for rule in grouping_rules)
            assert len(grouping_rules) == 3 # Count 'g' rules in default file

def test_save_policy_to_file(temp_model_file, tmp_path: Path):
    """Test saving policy to a file using FileAdapter."""
    # Use a fresh policy file for this test to check its content after save
    temp_policy_for_save = tmp_path / "policy_for_save.csv"
    temp_policy_for_save.touch() # Create the file so FileAdapter can load it (empty)

    enforcer = init_enforcer(model_path=temp_model_file, policy_adapter=temp_policy_for_save)
    from aphelion.authz.casbin_enforcer import add_policy_rule, save_policy_to_file

    # Add a rule, it's in memory
    add_policy_rule("user_save_test", "resource_save", "action_save")
    assert enforcer.enforce("user_save_test", "resource_save", "action_save")

    # File should be empty or not exist if adapter doesn't auto-save
    if temp_policy_for_save.exists():
        assert temp_policy_for_save.read_text().strip() == ""
        # Casbin FileAdapter creates the file if it doesn't exist on init, but it's empty.

    # Save policy
    assert save_policy_to_file() is True

    # Verify file content
    assert temp_policy_for_save.exists()
    content = temp_policy_for_save.read_text()
    assert "p, user_save_test, resource_save, action_save" in content

    # Test saving with a non-FileAdapter (mock the adapter)
    # This requires deeper mocking of how enforcer.adapter is set up.
    # For now, assume FileAdapter is used with path inputs.
    # If we had an adapter that doesn't support save_policy:
    # mock_adapter = MagicMock()
    # mock_adapter.save_policy.side_effect = Exception("Not supported")
    # enforcer.adapter = mock_adapter # Or init with this mock adapter
    # assert save_policy_to_file() is False # And check for logged warning
