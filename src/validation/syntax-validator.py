"""Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved"""
import os
import sys
import json
import logging
import re

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Stream handler to print logs on screen
console_handler= logging.StreamHandler()
console_handler.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

def log_and_append_error(message, errors, error_type="SYNTAX"):
    """
    Log an error message and append it to the errors list.
    """
    formatted_message = f"[{error_type}] {message}"
    logger.error(formatted_message)
    errors.append(formatted_message)

def validate_inline_policies(policies: dict) -> tuple[bool, list[str]]:
    """
    Validate the complete inline policies structure.
    Returns (is_valid, list_of_errors).
    """
    errors = []
    
    # Validate basic structure
    if not isinstance(policies, dict):
        errors.append("InlinePolicy must be a dictionary")
        return False, errors
    
    # Validate Version
    if "Version" not in policies:
        errors.append("Policy must contain 'Version'")
    elif policies["Version"] != "2012-10-17":
        errors.append("Policy Version must be '2012-10-17'")
    
    # Validate Statement
    if "Statement" not in policies:
        errors.append("Policy must contain 'Statement'")
        return False, errors
    
    statements = policies["Statement"]
    if not isinstance(statements, list):
        errors.append("Statement must be a list")
        return False, errors
    
    for idx, statement in enumerate(statements):
        is_valid, error = validate_inline_policy_statement(statement)
        if not is_valid:
            errors.append(f"Invalid statement at index {idx}: {error}")
    
    # Check policy size limit
    policy_json = json.dumps(policies)
    if len(policy_json) > 10240:
        errors.append("Policy document exceeds maximum size of 10,240 characters")
    
    return len(errors) == 0, errors

def validate_inline_policy_statement(statement: dict) -> tuple[bool, str]:
    """
    Validate an IAM policy statement.
    Returns (is_valid, error_message).
    """
    if not isinstance(statement, dict):
        return False, "Statement must be a dictionary"
    
    # Validate Effect
    if "Effect" not in statement:
        return False, "Statement must contain 'Effect'"
    if statement["Effect"] not in ["Allow", "Deny"]:
        return False, "Effect must be either 'Allow' or 'Deny'"
    
    # Validate Action/Resource
    if "Action" not in statement and "NotAction" not in statement:
        return False, "Statement must contain either 'Action' or 'NotAction'"
    if "Resource" not in statement and "NotResource" not in statement:
        return False, "Statement must contain either 'Resource' or 'NotResource'"
    
    # Validate Sid if present
    if "Sid" in statement:
        if not re.match(r'^[\w+=,.@-]+$', statement["Sid"]):
            return False, "Sid must contain only alphanumeric characters and [+=,.@-]"
    
    return True, ""

def validate_duplicate_ps_names(base_path: str) -> list[str]:
    """
    Verify if there are any duplicate permission set files.
    Returns a list of validation errors.
    """
    errors = []
    
    try:
        filenames = os.listdir(os.path.join(base_path, 'permission-sets'))
        seen_names = set()
        for filename in filenames:
            if filename.endswith('.json'):
                with open(os.path.join(base_path, 'permission-sets', filename), 'r') as f:
                    ps = json.load(f)
                    name = ps.get('Name')
                    if name in seen_names:
                        errors.append(f"Duplicate permission set name found: {name}")
                    seen_names.add(name)
        
    except Exception as e:
        errors.append(f"Error during duplicate permission set name validation: {str(e)}")
    
    return errors

def validate_whitespace(value: str, field_name: str) -> tuple[bool, str]:
    """Validate that a string value doesn't contain leading/trailing whitespace."""
    if value != value.strip():
        return False, f"{field_name} contains leading or trailing whitespace"
    return True, ""

def contains_only_whitespace(value: str) -> bool:
    """Check if a string consists only of whitespace characters."""
    return bool(value) and value.isspace()

def validate_file_name_matches_content(file_name: str, content_name: str) -> bool:
    """
    Validate that the JSON file name matches the Name field in content.
    Example: "admin-access.json" should contain {"Name": "admin-access"}
    """
    base_name = file_name.rsplit('.', 1)[0] if '.' in file_name else file_name
    return base_name == content_name

def verify_policy_name_matches_arn(name: str, arn: str) -> bool:
    """
    Verify that policy name matches the last part of the ARN.
    Examples:
    - name="AdministratorAccess", arn="arn:aws:iam::aws:policy/AdministratorAccess"
    - name="SupportUser", arn="arn:aws:iam::aws:policy/job-function/SupportUser"
    """
    try:
        arn_name = arn.split('/')[-1]
        return name == arn_name
    except:
        return False
    
def validate_description(description: str) -> bool:
    """
    Validate description format.
    Must be 1-256 characters, no control characters.
    """
    if not description or len(description) > 256:
        return False
    return not any(ord(char) < 32 for char in description)

def find_duplicate_policies(policies: list) -> set[str]:
    """
    Find duplicate policy ARNs in a list of policies.
    Returns a set of duplicate ARNs.
    """
    seen_arns = set()
    duplicates = set()
    
    for policy in policies:
        if "Arn" in policy:
            arn = policy["Arn"]
            if arn in seen_arns:
                duplicates.add(arn)
            seen_arns.add(arn)
    
    return duplicates

def validate_session_duration(duration: str) -> bool:
    """
    Validate ISO 8601 duration format for session duration.
    Must be in format PT[n]H where n is between 1-12.
    """
    pattern = r'^PT([1-9]|1[0-2])H$'
    return bool(re.match(pattern, duration))

def validate_account_id(account_id: str) -> bool:
    """
    Validate AWS account ID format.
    Must be 12 digits (no leading zeros), "Global" for global mappings, start with "name:" for account names and "ou:" for organization units.
    """
    if account_id == "Global":
        return True
    if account_id.startswith('0'):
        return False
    if account_id.startswith('name:') or account_id.startswith('ou:'):
        return True
    return bool(re.match(r'^[1-9]\d{11}$', account_id))

def validate_permission_set_name(name: str) -> bool:
    """
    Validate permission set name.
    Must be 1-32 characters, alphanumeric and [-_] only.
    """
    return bool(re.match(r'^[\w-]{1,32}$', name))

def validate_tag_key(key: str) -> bool:
    """
    Validate AWS tag key.
    Must be 1-128 characters and not start with aws:.
    """
    if len(key) < 1 or len(key) > 128:
        return False
    return not key.lower().startswith(('aws:', 'amazon:', 'aws-'))

def validate_tag_value(value: str) -> bool:
    """
    Validate AWS tag value.
    Must be 0-256 characters.
    """
    return len(value) <= 256

def validate_permission_set_schema(permission_set, errors):
    """
    Validate the permission set schema including format validations.
    Example of valid permission set:
    {
        "Name": "example-admin",
        "Description": "Admin access",
        "Session_Duration": "PT12H",
        "Tags": [{"Key": "env", "Value": "prod"}],
        "ManagedPolicies": [{"Name": "Admin", "Arn": "arn:aws:iam::aws:policy/Admin"}],
        "InlinePolicies": []
    }
    """
    """
    Validate the permission set schema including format validations.
    """
    logger.info(f"Validating permission set schema for {permission_set}")

    required_keys = {
        "Name": str,
        "ManagedPolicies": list,
        "InlinePolicies": (list, dict)
    }

    optional_keys = {
        "Description": str,
        "Tags": list,
        "CustomerPolicies": list,
        "Session_Duration": str
    }

    for key in permission_set.keys():
        if key.lower() != key and key not in {"Name", "Description", "Session_Duration", "Tags", "ManagedPolicies", "CustomerPolicies", "InlinePolicies"}:
            log_and_append_error(f"Inconsistent key casing: found '{key}' but expected standard casing", errors)

    permission_set_name = permission_set.get('Name', 'Unknown')
    if 'Description' in permission_set:
        if contains_only_whitespace(permission_set['Description']):
            log_and_append_error(f"Description in permission set {permission_set_name} cannot be only whitespace", errors)
        elif not validate_description(permission_set['Description']):
            log_and_append_error(f"Invalid Description in permission set {permission_set_name}. Must be 1-256 characters with no control characters", errors)
        
    # Check for duplicate policies
    duplicate_arns = find_duplicate_policies(permission_set.get("ManagedPolicies", []))
    if duplicate_arns:
        log_and_append_error(f"Duplicate policy ARNs found in permission set {permission_set_name}: {', '.join(duplicate_arns)}", errors)
    
    # Validate permission set name format
    if contains_only_whitespace(permission_set_name):
        log_and_append_error(f"Permission set name cannot be only whitespace", errors)
    elif not validate_permission_set_name(permission_set_name):
        log_and_append_error(f"Permission set name '{permission_set_name}' must be 1-32 characters, alphanumeric and [-_] only", errors)

    # Validate session duration if present
    if 'Session_Duration' in permission_set:
        duration = permission_set['Session_Duration']
        if not validate_session_duration(duration):
            log_and_append_error(f"Invalid Session_Duration format '{duration}' in permission set {permission_set_name}. Must be in format PT[n]H where n is 1-12", errors)

    # Validate required keys
    for key, expected_type in required_keys.items():
        if key not in permission_set:
            log_and_append_error(f"Missing required key: {key} in permission set {permission_set_name}", errors)
            continue
        if not isinstance(permission_set[key], expected_type):
            log_and_append_error(f"Key '{key}' is not of expected type {expected_type.__name__} in permission set {permission_set_name}", errors)

    # Check for unknown keys
    allowed_keys = set(required_keys.keys()) | set(optional_keys.keys())
    unknown_keys = set(permission_set.keys()) - allowed_keys
    if unknown_keys:
        log_and_append_error(f"Unknown keys found in permission set {permission_set_name}: {', '.join(unknown_keys)}", errors)

    policy_count = len(permission_set.get("ManagedPolicies", []))
    if policy_count > 20:
        log_and_append_error(f"Permission set {permission_set_name} has {policy_count} managed policies. Maximum allowed is 20", errors)
    
    if 'Tags' in permission_set:
        for tag in permission_set["Tags"]:
            if not isinstance(tag, dict) or "Key" not in tag or "Value" not in tag:
                log_and_append_error(f"Each tag must be a dictionary with 'Key' and 'Value' fields in permission set {permission_set_name}", errors)
            else:
                if not validate_tag_key(tag["Key"]):
                    log_and_append_error(f"Invalid tag key '{tag['Key']}' in permission set {permission_set_name}. Must be 1-128 chars and not start with aws:", errors)
                if not validate_tag_value(tag["Value"]):
                    log_and_append_error(f"Invalid tag value length for key '{tag['Key']}' in permission set {permission_set_name}. Must be 0-256 chars", errors)

    for policy in permission_set["ManagedPolicies"]:
        if not isinstance(policy, dict) or "Name" not in policy or "Arn" not in policy:
            log_and_append_error(f"Each managed policy must be a dictionary with 'Name' and 'Arn' fields in permission set {permission_set_name}", errors)
        elif not verify_policy_name_matches_arn(policy["Name"], policy["Arn"]):
            log_and_append_error(f"Policy name '{policy['Name']}' does not match ARN basename in {permission_set_name}", errors)
    
    # Validate CustomerPolicies if present
    if "CustomerPolicies" in permission_set:
        customer_policies = permission_set["CustomerPolicies"]
        if not isinstance(customer_policies, list):
            log_and_append_error(f"CustomerPolicies must be a list in permission set {permission_set_name}", errors)
        else:
            for policy in customer_policies:
                if not isinstance(policy, dict) or "Name" not in policy or "Path" not in policy:
                    log_and_append_error(f"Each customer policy must be a dictionary with 'Name' and 'Path' fields in permission set {permission_set_name}", errors)

    inline_policies = permission_set["InlinePolicies"]
    if isinstance(inline_policies, list):
        if inline_policies:
            log_and_append_error(f"InlinePolicies list must be empty [] in permission set {permission_set_name}", errors)
    elif isinstance(inline_policies, dict):
        is_valid, policy_errors = validate_inline_policies(inline_policies)
        if not is_valid:
            for error in policy_errors:
                log_and_append_error(f"InlinePolicy error in {permission_set_name}: {error}", errors)
    else:
        log_and_append_error(f"InlinePolicies must be either a list or a dictionary in permission set {permission_set_name}", errors)

def validate_permission_set_references(permission_sets: list[str], errors: list) -> None:
    """Validate individual permission set names in references."""
    for ps_name in permission_sets:
        if contains_only_whitespace(ps_name):
            log_and_append_error(f"Permission set name '{ps_name}' cannot be only whitespace", errors)
        elif not ps_name:
            log_and_append_error("Empty permission set name found", errors)

def validate_mapping_file_structure(permission_set_file, group_type, errors):
    def check_permission_set_name_format(items: list) -> bool:
        """Check if all items use the same format (string or list) for PermissionSetName"""
        has_string = any(isinstance(item.get('PermissionSetName'), str) for item in items)
        has_list = any(isinstance(item.get('PermissionSetName'), list) for item in items)
        return not (has_string and has_list)  # Should not have both formats
    """
    Validate the structure of the permission set mapping file.
    Example of valid global mapping:
    [
        {
            "GlobalGroupName": "Admin_Group",
            "PermissionSetName": ["example-admin"],
            "TargetAccountid": "Global"
        }
    ]
    Example of valid target mapping:
    [
        {
            "TargetGroupName": "Dev_Group",
            "PermissionSetName": ["dev-access"],
            "TargetAccountid": ["123456789012"]
        }
    ]
    """
    """
    Validate the structure of the permission set mapping file.
    """
    logger.info(f"Validating file structure for {group_type} mapping")

    required_keys = {
        "PermissionSetName": list    
    }

    if group_type == 'global':
        group_key = 'GlobalGroupName'
        target_accountid_type = str
        # In global mapping, TargetAccountid must be "Global"
        for idx, item in enumerate(permission_set_file):
            if item.get('TargetAccountid') != 'Global':
                log_and_append_error(f"Global mapping must use 'Global' for TargetAccountid at index {idx}", errors)
    elif group_type == 'target':  # target
        group_key = 'TargetGroupName'
        target_accountid_type = list
        # In target mapping, TargetAccountid must never be "Global"
        for idx, item in enumerate(permission_set_file):
            if isinstance(item.get('TargetAccountid'), list):
                if 'Global' in item['TargetAccountid']:
                    log_and_append_error(f"Target mapping cannot use 'Global' for TargetAccountid at index {idx}", errors)
            elif item.get('TargetAccountid') == 'Global':
                log_and_append_error(f"Target mapping cannot use 'Global' for TargetAccountid at index {idx}", errors)
    
    # Check for consistent PermissionSetName format usage
    if not check_permission_set_name_format(permission_set_file):
        log_and_append_error(f"Inconsistent format for PermissionSetName in {group_type} mapping. Use list format consistently", errors)

    # Additional validation logic copied from auto-assignment.py
    if not isinstance(permission_set_file, list):
        log_and_append_error("The mapping file must be a list", errors)
        return

    for idx, permission_set in enumerate(permission_set_file):
        if not isinstance(permission_set, dict):
            log_and_append_error(f"Each item in the mapping file must be a dictionary. Item at index {idx} is not a dictionary.", errors)
            continue
        
        if group_key not in permission_set:
            log_and_append_error(f"Missing required key: '{group_key}' in mapping file at index {idx}", errors)
        group_name = permission_set[group_key]
        is_valid, msg = validate_whitespace(group_name, group_key)
        if not is_valid:
            log_and_append_error(f"{msg} at index {idx}", errors)
        
        if not isinstance(permission_set.get(group_key), str):
            log_and_append_error(f"Key '{group_key}' is not of expected type str at index {idx}", errors)

        for key, expected_type in required_keys.items():
            if key not in permission_set:
                log_and_append_error(f"Missing required key: {key} in permission set at index {idx}", errors)
            elif not isinstance(permission_set[key], expected_type):
                log_and_append_error(f"Key '{key}' is not of expected type {expected_type.__name__} in permission set at index {idx}", errors)

        if "TargetAccountid" not in permission_set:
            log_and_append_error(f"Missing required key: 'TargetAccountid' in mapping at index {idx}", errors)
        
        elif not isinstance(permission_set["TargetAccountid"], target_accountid_type):
            log_and_append_error(f"'TargetAccountid' must be of type {target_accountid_type.__name__} in mapping file at index {idx}", errors)
        
        elif isinstance(permission_set["TargetAccountid"], str):
            if not validate_account_id(permission_set["TargetAccountid"]):
                log_and_append_error(f"Invalid TargetAccountid '{permission_set['TargetAccountid']}' at index {idx}. Must be 12 digits or 'Global'", errors)
        elif isinstance(permission_set["TargetAccountid"], list):
            for account_id in permission_set["TargetAccountid"]:
                if not validate_account_id(account_id):
                    log_and_append_error(f"Invalid TargetAccountid '{account_id}' at index {idx}. Must be 12 digits or 'Global'", errors)

        if "PermissionSetName" in permission_set:
            if not all(isinstance(item, str) for item in permission_set["PermissionSetName"]):
                log_and_append_error(f"All items in 'PermissionSetName' must be strings in permission sets at index {idx}", errors)
            else:
                validate_permission_set_references(permission_set["PermissionSetName"], errors)
        
        if group_type == "target" and "TargetAccountid" in permission_set and not all(isinstance(item, str) for item in permission_set["TargetAccountid"]):
            log_and_append_error(f"All items in the list 'TargetAccountid' must be strings in account IDs at index {idx}", errors)

def validate_all_files():
    """
    Main function to validate all permission set and mapping files from the git repository.
    """
    errors = []
    try:
        base_path = 'identity-center-mapping-info'
        
        # Validate permission set JSON files
        permission_sets_path = os.path.join(base_path, 'permission-sets')
        try:
            for filename in os.listdir(permission_sets_path):
                if filename.endswith('.json'):
                    file_path = os.path.join(permission_sets_path, filename)
                    logger.info(f"Opening {filename} permission set file")
                    try:
                        with open(file_path, 'r') as file:
                            try:
                                permission_set = json.load(file)
                                if 'Name' in permission_set:
                                    if not validate_file_name_matches_content(filename, permission_set['Name']):
                                        log_and_append_error(f"File name '{filename}' does not match permission set Name '{permission_set['Name']}'", errors)
                                validate_permission_set_schema(permission_set, errors)
                                logger.info(f"Completed validation of permission set file: {filename}")
                            except json.JSONDecodeError as e:
                                log_and_append_error(f"Invalid JSON format in {filename}: {str(e)}", errors)
                    except (FileNotFoundError, PermissionError) as e:
                        log_and_append_error(f"Error accessing {filename}: {str(e)}", errors)
        except (FileNotFoundError, PermissionError) as e:
            log_and_append_error(f"Error accessing permission sets directory: {str(e)}", errors)

        # Validate global mapping file
        global_mapping_path = os.path.join(base_path, 'global-mapping.json')
        logger.info(f"Opening global-mapping.json")
        try:
            with open(global_mapping_path, 'r') as file:
                try:
                    global_content = json.load(file)
                    validate_mapping_file_structure(global_content, 'global', errors)
                    logger.info("Completed validation of global mapping file")
                except json.JSONDecodeError as e:
                    log_and_append_error(f"Invalid JSON format in global-mapping.json: {str(e)}", errors)
        except (FileNotFoundError, PermissionError) as e:
            log_and_append_error(f"Error accessing global mapping file: {str(e)}", errors)

        # Validate target mapping file
        target_mapping_path = os.path.join(base_path, 'target-mapping.json')
        logger.info(f"Opening target-mapping.json")
        try:
            with open(target_mapping_path, 'r') as file:
                try:
                    target_content = json.load(file)
                    validate_mapping_file_structure(target_content, 'target', errors)
                    logger.info("Completed validation of target mapping file")
                except json.JSONDecodeError as e:
                    log_and_append_error(f"Invalid JSON format in target-mapping.json: {str(e)}", errors)
        except (FileNotFoundError, PermissionError) as e:
            log_and_append_error(f"Error accessing target mapping file: {str(e)}", errors)

        # Perform duplicates validation
        duplicate_ps_errors = validate_duplicate_ps_names(base_path)
        if duplicate_ps_errors:
            for error in duplicate_ps_errors:
                log_and_append_error(error, errors)

        if errors:
            error_message = "\n".join(errors)
            logger.info(f"Validation failed with the following errors:\n{error_message}")
            sys.exit(1) # Signal failure to CodeBuild
        else:
            logger.info("All validation checks completed successfully")
            return True
        
    except Exception as error:
        error_message = f'Exception caught: {error}'
        logger.error(error_message)
        log_and_append_error(error_message)
        if errors:
            logger.error(f'Errors during execution: {errors}')
        sys.exit(1) # Signal failure to CodeBuild

if __name__ == "__main__":
    try:
        validate_all_files()
    except Exception as e:
        logger.error(f"Validation failed: {str(e)}")
        sys.exit(1)