# src/aphelion/authz/casbin_enforcer.py

import casbin
from pathlib import Path
from typing import Optional, Any, Union # Added Union

from aphelion.config import get_config, AppConfigModel # Assuming config might influence paths

# --- Constants for default paths ---
# These paths are relative to the project root.
# config.py defines BASE_DIR as project root.
CONFIG_BASE_DIR = Path(__file__).resolve().parent.parent.parent / "config"
DEFAULT_MODEL_PATH = CONFIG_BASE_DIR / "rbac_model.conf"
DEFAULT_POLICY_PATH = CONFIG_BASE_DIR / "rbac_policy.csv"

# --- Global Enforcer Instance ---
_enforcer: Optional[casbin.Enforcer] = None

# --- Custom Exceptions ---
class PolicyError(Exception):
    """Raised for issues related to policy loading or model errors."""
    pass

class AuthorizationError(Exception):
    """Base class for authorization failures."""
    pass

class NotAuthorizedError(AuthorizationError):
    """Raised when a subject is not authorized for a specific action on an object."""
    def __init__(self, subject: Any, obj: Any, action: Any, message: Optional[str] = None):
        self.subject = subject
        self.obj = obj
        self.action = action
        if message is None:
            message = f"Subject '{subject}' is not authorized to '{action}' on object '{obj}'."
        super().__init__(message)

# --- Enforcer Initialization and Access ---

def init_enforcer(
    model_path: Optional[Union[str, Path]] = None,
    policy_adapter: Optional[Union[str, Path, object]] = None
) -> casbin.Enforcer:
    """
    Initializes and returns a Casbin enforcer instance.
    If an enforcer is already initialized, it returns the existing one unless paths are different.
    This function should ideally be called once at application startup.

    :param model_path: Path to the Casbin model configuration file (.conf).
                       Defaults to DEFAULT_MODEL_PATH.
    :param policy_adapter: Path to the Casbin policy file (.csv) or a Casbin Adapter instance.
                           Defaults to DEFAULT_POLICY_PATH (CSV file adapter).
    :return: A Casbin Enforcer instance.
    :raises PolicyError: If the model or policy file is not found or is invalid.
    """
    global _enforcer

    # Determine effective paths using app configuration if available, or defaults
    # This part could be enhanced if AppConfigModel stores model/policy paths.
    # For now, direct params or defaults are used.

    eff_model_path = Path(model_path or DEFAULT_MODEL_PATH)

    # If policy_adapter is a path, make it Path object. Otherwise, assume it's an Adapter instance.
    if isinstance(policy_adapter, (str, Path)):
        eff_policy_adapter = Path(policy_adapter or DEFAULT_POLICY_PATH)
    else: # It's an adapter instance or None (which means use default path)
        eff_policy_adapter = policy_adapter or DEFAULT_POLICY_PATH


    # Simple check: if paths are the same as current enforcer, return it.
    # This is a basic way to avoid re-init if params are identical.
    # A more robust check would involve comparing model/policy content or adapter state.
    if _enforcer and hasattr(_enforcer, '_current_model_path') and hasattr(_enforcer, '_current_policy_adapter_path'):
        current_model_matches = Path(_enforcer._current_model_path) == eff_model_path
        current_policy_matches = True # Assume matches if adapter object is used
        if isinstance(eff_policy_adapter, Path) and isinstance(_enforcer._current_policy_adapter_path, Path):
             current_policy_matches = Path(_enforcer._current_policy_adapter_path) == eff_policy_adapter
        elif type(eff_policy_adapter) != type(_enforcer._current_policy_adapter_path): # one is path, other is adapter obj
            current_policy_matches = False

        if current_model_matches and current_policy_matches:
            return _enforcer

    try:
        if not eff_model_path.exists():
            raise PolicyError(f"Casbin model file not found: {eff_model_path}")

        # If policy adapter is a path, Casbin's FileAdapter will handle it.
        # It can create the file if it doesn't exist when saving,
        # or load from it if it exists. So, no strict check here for existence
        # unless we are absolutely sure it must exist for loading.
        # if isinstance(eff_policy_adapter, Path) and not eff_policy_adapter.exists():
        #     # This check might be too strict if the file is meant to be created by save_policy.
        #     # Casbin's FileAdapter itself doesn't fail on init if file is missing.
        #     raise PolicyError(f"Casbin policy file not found: {eff_policy_adapter}")

        # Casbin's FileAdapter is used by default if a string path is provided for the policy.
        # For other adapters (like SQLAlchemy), they would be passed in as policy_adapter object.
        # Ensure policy adapter path is also stringified if it's a Path object for casbin.Enforcer constructor.
        policy_arg = str(eff_policy_adapter) if isinstance(eff_policy_adapter, Path) else eff_policy_adapter
        e = casbin.Enforcer(str(eff_model_path), policy_arg)

        # Store paths on enforcer for simple re-init check (optional enhancement)
        e._current_model_path = eff_model_path
        e._current_policy_adapter_path = eff_policy_adapter

        _enforcer = e
        return _enforcer
    except Exception as e: # Catch generic casbin errors during init
        # Log the error e
        raise PolicyError(f"Failed to initialize Casbin enforcer: {e}")


def get_enforcer() -> casbin.Enforcer:
    """
    Retrieves the global Casbin enforcer instance.
    Initializes it with default paths if it hasn't been initialized yet.

    :return: The global Casbin Enforcer instance.
    :raises PolicyError: If the enforcer is not initialized and fails to initialize.
    """
    if _enforcer is None:
        # Attempt to initialize with defaults or paths from config if available
        # app_cfg = get_config()
        # model_p = app_cfg.authz.model_file if hasattr(app_cfg, 'authz') else DEFAULT_MODEL_PATH
        # policy_p = app_cfg.authz.policy_file if hasattr(app_cfg, 'authz') else DEFAULT_POLICY_PATH
        # return init_enforcer(model_p, policy_p)
        return init_enforcer() # Uses hardcoded defaults for now
    return _enforcer

# --- Authorization Check ---

def enforce(subject: Any, obj: Any, action: Any) -> bool:
    """
    Performs an authorization check using the Casbin enforcer.

    :param subject: The subject (e.g., user ID, role name) requesting access.
    :param obj: The object (e.g., resource name, data entity) being accessed.
    :param action: The action (e.g., read, write, execute) being performed.
    :return: True if authorized, False otherwise.
    :raises PolicyError: If the enforcer is not initialized.
    """
    enforcer = get_enforcer()
    if not enforcer.enforce(str(subject), str(obj), str(action)):
        # Optionally, could raise NotAuthorizedError here directly,
        # or let the caller decide based on the boolean.
        # For now, returning False is consistent with enforcer.enforce()
        return False
    return True

# --- Policy Management Functions ---

def add_policy_rule(subject: Any, obj: Any, action: Any) -> bool:
    """
    Adds a single policy rule to the current Casbin enforcer.
    Example: add_policy_rule("user1", "data1", "read")
    Note: This modifies the in-memory policy. Call save_policy_to_file() to persist if using FileAdapter.
    """
    enforcer = get_enforcer()
    # Casbin's add_policy expects variadic string arguments, not a list.
    # For ptype 'p', it's typically (sub, obj, act)
    # For gtype 'g', it's typically (user, role, optional_domain)
    # This function assumes a standard 'p' policy rule.
    # For more general rule addition, use enforcer.add_named_policy("p", [...])
    # or enforcer.add_policy(...) with appropriate number of string args.
    # The add_policy method itself returns True if rule added, False if already exists.
    return enforcer.add_policy(str(subject), str(obj), str(action))

def remove_policy_rule(subject: Any, obj: Any, action: Any) -> bool:
    """
    Removes a single policy rule from the current Casbin enforcer.
    Note: This modifies the in-memory policy. Call save_policy_to_file() to persist if using FileAdapter.
    """
    enforcer = get_enforcer()
    return enforcer.remove_policy(str(subject), str(obj), str(action))

def add_grouping_policy_rule(user: Any, role: Any, domain: Optional[str] = None) -> bool:
    """
    Adds a role assignment (grouping policy).
    Example: add_grouping_policy_rule("alice", "admin")
    Note: This modifies the in-memory policy. Call save_policy_to_file() to persist.
    """
    enforcer = get_enforcer()
    if domain:
        return enforcer.add_grouping_policy(str(user), str(role), str(domain))
    return enforcer.add_grouping_policy(str(user), str(role))

def remove_grouping_policy_rule(user: Any, role: Any, domain: Optional[str] = None) -> bool:
    """
    Removes a role assignment (grouping policy).
    Note: This modifies the in-memory policy. Call save_policy_to_file() to persist.
    """
    enforcer = get_enforcer()
    if domain:
        return enforcer.remove_grouping_policy(str(user), str(role), str(domain))
    return enforcer.remove_grouping_policy(str(user), str(role))

def get_all_policy_rules() -> list[list[str]]:
    """Returns all policy rules from the enforcer."""
    enforcer = get_enforcer()
    return enforcer.get_policy()

def get_all_grouping_policy_rules() -> list[list[str]]:
    """Returns all grouping policy rules (role assignments) from the enforcer."""
    enforcer = get_enforcer()
    return enforcer.get_grouping_policy()

def save_policy_to_file() -> bool:
    """
    Saves the current in-memory policy back to the policy file
    if the adapter supports it (e.g., FileAdapter).
    This is a no-op for adapters that auto-save or don't use files.
    Returns True if save was attempted (actual success depends on adapter).
    """
    enforcer = get_enforcer()
    # The save_policy method is part of the Adapter API that the Enforcer can call.
    # Casbin's FileAdapter implements save_policy.
    # If no adapter or a non-saving adapter, this might do nothing or error.
    # The Enforcer's save_policy method calls the adapter's save_policy.
    try:
        enforcer.save_policy()
        return True
    except Exception as e:
        # Log this error, e.g., "Adapter does not support saving: {e}"
        # For now, we'll assume it might fail if adapter doesn't support it.
        print(f"Warning: Could not save policy, adapter might not support it or error occurred: {e}")
        return False


# --- Example Usage (for testing or direct script execution) ---
if __name__ == "__main__":
    print(f"Default Model Path: {DEFAULT_MODEL_PATH}")
    print(f"Default Policy Path: {DEFAULT_POLICY_PATH}")

    try:
        # Initialize with default model and policy files
        e = init_enforcer()
        print("Casbin enforcer initialized successfully.")

        # Example checks (assuming default rbac_policy.csv content)
        # 1. Admin alice wants to read data_resource_1
        sub_alice_admin = "alice" # alice is admin via g, alice, admin
        obj_data1 = "data_resource_1"
        act_read = "read"
        act_write = "write"

        if enforce(sub_alice_admin, obj_data1, act_read):
            print(f"'{sub_alice_admin}' CAN '{act_read}' on '{obj_data1}'")
        else:
            print(f"'{sub_alice_admin}' CANNOT '{act_read}' on '{obj_data1}' (ERROR if policy implies allow)")

        # 2. Editor bob wants to write to data_resource_1
        sub_bob_editor = "bob" # bob is editor via g, bob, editor
        if enforce(sub_bob_editor, obj_data1, act_write):
            print(f"'{sub_bob_editor}' CAN '{act_write}' on '{obj_data1}'")
        else:
            print(f"'{sub_bob_editor}' CANNOT '{act_write}' on '{obj_data1}' (ERROR if policy implies allow)")

        # 3. Viewer cathy wants to write to data_resource_1
        sub_cathy_viewer = "cathy" # cathy is viewer
        if enforce(sub_cathy_viewer, obj_data1, act_write):
            print(f"'{sub_cathy_viewer}' CAN '{act_write}' on '{obj_data1}' (ERROR - should be denied)")
        else:
            print(f"'{sub_cathy_viewer}' CANNOT '{act_write}' on '{obj_data1}' (Correctly denied)")

        # 4. Non-existent user/role
        sub_nobody = "nobody"
        if enforce(sub_nobody, obj_data1, act_read):
            print(f"'{sub_nobody}' CAN '{act_read}' on '{obj_data1}' (ERROR - should be denied)")
        else:
            print(f"'{sub_nobody}' CANNOT '{act_read}' on '{obj_data1}' (Correctly denied)")

        # 5. Admin trying to access something not explicitly in policy (but roles might cover via wildcards if model supports)
        # Our current model is exact match.
        obj_new_tool = "tool_gamma"
        act_execute = "execute"
        if enforce(sub_alice_admin, obj_new_tool, act_execute):
             print(f"'{sub_alice_admin}' CAN '{act_execute}' on '{obj_new_tool}' (Allowed by a broad policy or role?)")
        else:
            print(f"'{sub_alice_admin}' CANNOT '{act_execute}' on '{obj_new_tool}' (Denied as expected with exact match policies)")


    except PolicyError as pe:
        print(f"Policy Error: {pe}")
    except Exception as ex:
        print(f"An unexpected error occurred: {ex}")

    # Example of how to use NotAuthorizedError (if enforce were to raise it)
    # try:
    #     if not enforce_raising(sub_cathy_viewer, obj_data1, act_write): # Imaginary enforce_raising
    #          pass # Or handle boolean if it still returns one
    # except NotAuthorizedError as nae:
    #     print(f"Caught expected auth error: {nae}")

    # Reset enforcer for potential subsequent tests in other modules if this were imported
    _enforcer = None
