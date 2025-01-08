"""Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved"""
# pylint: disable=C0301
# pylint: disable=W1202,W0703
# pylint: disable=E0401
import os
import json
import logging
import sys
from time import sleep
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config
import watchtower

AWS_CONFIG = Config(
    retries=dict(
        max_attempts=8,
        mode='standard'
    )
)

runtime_region = os.getenv('AWS_REGION')
global_mapping_file_name = os.getenv('GlobalFileName')
identity_store_id = os.getenv('IdentityStore_Id')
identitystore_client = boto3.client(
    'identitystore', region_name=runtime_region, config=AWS_CONFIG)
orgs_client = boto3.client(
    'organizations', region_name=runtime_region, config=AWS_CONFIG)
pipeline = boto3.client(
    'codepipeline', region_name=runtime_region, config=AWS_CONFIG)
s3client = boto3.client('s3', region_name=runtime_region, config=AWS_CONFIG)
ic_admin = boto3.client(
    'sso-admin', region_name=runtime_region, config=AWS_CONFIG)
ic_bucket_name = os.getenv('IC_S3_BucketName')
ic_instance_arn = os.getenv('IC_InstanceArn')
target_mapping_file_name = os.getenv('TargetFileName')
management_account_id = os.getenv('Org_Management_Account')
delegated = os.getenv('AdminDelegated')
event_env = os.getenv("EVENT_DATA")
logs_client = boto3.client(
    'logs', region_name=runtime_region, config=AWS_CONFIG)
assignment_automation_log_group = os.getenv('AssignmentAutomationLogGroupName')
codebuild_build_id = os.getenv('CODEBUILD_BUILD_ID')
build_name, build_id = codebuild_build_id.split(':')
if event_env:
    event = event_env
else:
    event = None
build_initiator = os.getenv("CODEBUILD_INITIATOR")
pipeline_execution_id = os.getenv('CODEPIPELINE_EXECUTION_ID')
commit_id = os.getenv('COMMIT_ID')
skipped_perm_set = {}


logger = logging.getLogger()
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Watchtower handler to send logs to CloudWatch
watchtower_handler = watchtower.CloudWatchLogHandler(
    log_group=assignment_automation_log_group,
    stream_name=f"[buildId]-{build_id}",
    boto3_client=logs_client
)
formatter_no_timestamp = logging.Formatter('%(levelname)s - %(message)s')
watchtower_handler.setFormatter(formatter_no_timestamp)
logger.addHandler(watchtower_handler)

boto_logger = logging.getLogger('botocore')
boto_logger.setLevel(logging.DEBUG)

# Add boto3 logger to log API retry events
for handler in logger.handlers:
    boto_logger.addHandler(handler)


class RetryFilter(logging.Filter):
    def filter(self, record):
        return 'Retry needed' in record.getMessage()


boto_logger.addFilter(RetryFilter())


def log_and_append_error(message):
    logger.error(message)
    errors.append(message)


logger.info("Logging initialized")


def get_valid_group_id(group_name):
    try:
        logger.debug(f"Getting group ID for group name: {group_name}")
        group_id = get_groupid(group_name)
        return group_id
    except identitystore_client.exceptions.ResourceNotFoundException as error:
        log_and_append_error(
            f'"{group_name}" not found in Identity Center: {error}')
        return None
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)
        return None


def get_permission_set_arn(permission_set_name, current_aws_permission_sets):
    """Get permission set by name"""
    logger.debug(f"Looking up permission set ARN for: {permission_set_name}")
    try:
        arn = current_aws_permission_sets[permission_set_name]['Arn']
        logger.debug(
            f"Found ARN for permission set {permission_set_name}: {arn}")
        return arn
    except KeyError as error:
        # Check if permission set exists in skipped permission set list
        skipped = False
        for perm_set_arn, perm_set_name in skipped_perm_set.items():
            if permission_set_name == perm_set_name:
                skipped = True
                logger.warning(
                    'WARNING: Permission set %s already exists and is either managed by Control Tower, or provisioned in the management account. \
                    Please create a different permission set that will not be provisioned in the management account or not managed by Control Tower.', permission_set_name)
                break
        if not skipped:
            error_message = f'PermissionSet: {permission_set_name} not found. Skipping assignment.'
            log_and_append_error(error_message)
        return None


def get_account_id_by_name(account_name):
    """Get AWS account ID from account name"""
    logger.debug(f"Looking up account ID for account name: {account_name}")
    try:
        paginator = orgs_client.get_paginator('list_accounts')
        for page in paginator.paginate():
            for account in page['Accounts']:
                if account['Name'] == account_name:
                    return account['Id']
        logger.warning(f"No account found with name: {account_name}")
        return None
    except ClientError as error:
        log_and_append_error(
            f"Error getting account ID for name {account_name}: {error}")
        return None
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)
        return None


def find_ou_id(parent_id, ou_name):
    """Recursively search for OU ID by name through all levels"""
    try:
        paginator = orgs_client.get_paginator(
            'list_organizational_units_for_parent')

        for page in paginator.paginate(ParentId=parent_id):
            for ou in page['OrganizationalUnits']:
                if ou['Name'] == ou_name:
                    return ou['Id']
                nested_ou_id = find_ou_id(ou['Id'], ou_name)
                if nested_ou_id:
                    return nested_ou_id
        return None
    except orgs_client.exceptions.ParentNotFoundException:
        return None


def get_accounts_in_ou(ou_name):
    """Get list of account IDs in an organizational unit by OU name, including nested OUs"""
    account_ids = []
    try:
        root_response = orgs_client.list_roots()
        root_id = root_response['Roots'][0]['Id']

        ou_id = find_ou_id(root_id, ou_name)

        if not ou_id:
            logger.warning(f"No OU found with name: {ou_name}")
            return account_ids

        def get_all_accounts_in_ou(parent_id):
            """Recursively get all accounts in an OU and its child OUs"""
            ou_accounts = []
            # Get direct accounts
            paginator = orgs_client.get_paginator('list_accounts_for_parent')
            for page in paginator.paginate(ParentId=parent_id):
                for account in page['Accounts']:
                    if account['Status'] == 'ACTIVE':
                        ou_accounts.append(account['Id'])

            # Get accounts from child OUs
            child_paginator = orgs_client.get_paginator('list_children')
            for page in child_paginator.paginate(ParentId=parent_id, ChildType='ORGANIZATIONAL_UNIT'):
                for child in page['Children']:
                    ou_accounts.extend(get_all_accounts_in_ou(child['Id']))

            return ou_accounts

        account_ids = get_all_accounts_in_ou(ou_id)
        return account_ids

    except ClientError as error:
        log_and_append_error(
            f"Error getting accounts for OU {ou_name}: {error}")
        return account_ids
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)
        return account_ids


def list_all_current_account_assignment(acct_list, current_aws_permission_sets):
    """List all the current account assignments information"""
    all_assignments = []
    logger.info("Scanning current group assignments. This may take some time...")
    for each_perm_set_name in current_aws_permission_sets:
        try:
            for account in acct_list:
                if account['Status'] not in ["SUSPENDED", "PENDING_CLOSURE"]:
                    response = ic_admin.list_account_assignments(
                        InstanceArn=ic_instance_arn,
                        AccountId=str(account['Id']),
                        PermissionSetArn=current_aws_permission_sets[each_perm_set_name]['Arn'],
                        MaxResults=100
                    )
                    account_assignment = response['AccountAssignments']
                    while 'NextToken' in response:
                        response = ic_admin.list_account_assignments(
                            InstanceArn=ic_instance_arn,
                            AccountId=str(account['Id']),
                            PermissionSetArn=current_aws_permission_sets[each_perm_set_name]['Arn'],
                            MaxResults=100,
                            NextToken=response['NextToken']
                        )
                        account_assignment += response['AccountAssignments']
                        logger.info("Account %s assigment: %s",
                                    account['Id'], response['AccountAssignments'])
                        sleep(0.1)  # Aviod hitting API limit.
                    sleep(0.1)
                    # Eliminate the empty assignment responses.
                    if len(account_assignment) != 0:
                        for each_assignment in account_assignment:
                            ################################################################
                            # This Env only allows 'GROUP' assignee rather than 'USER' #
                            ################################################################
                            if str(each_assignment['PrincipalType']) == "USER":
                                delete_user_assignment = ic_admin.delete_account_assignment(
                                    InstanceArn=ic_instance_arn,
                                    TargetId=each_assignment['AccountId'],
                                    TargetType='AWS_ACCOUNT',
                                    PermissionSetArn=each_assignment['PermissionSetArn'],
                                    PrincipalType=each_assignment['PrincipalType'],
                                    PrincipalId=each_assignment['PrincipalId']
                                )
                                logger.info("PrincipalType 'USER' is not recommended in this solution,\
                                    remove USER assignee:%s", delete_user_assignment)
                            # After removing USER assignee, append all other GROUP assignee to the list.
                            else:
                                all_assignments.append(each_assignment)
        except Exception as error:
            error_message = f'Exception listing current account assignments: {error}'
            log_and_append_error(error_message)
    logger.debug("Current GROUP assignments: %s", all_assignments)
    return all_assignments


def drift_detect_update(all_assignments, global_file_contents,
                        target_file_contents, current_aws_permission_sets):
    """Use new mapping information to update IAM Identity Center assignments"""
    logger.info('Starting assignment drift detection')
    check_list = all_assignments
    remove_list = []
    for each_assignment in check_list:
        try:
            logger.debug("list each global assignment:%s", each_assignment)
            for global_mapping in global_file_contents:
                for each_perm_set_name in global_mapping['PermissionSetName']:
                    global_group_id = get_valid_group_id(
                        global_mapping['GlobalGroupName'])
                    if not global_group_id:
                        continue
                    permission_set_arn = get_permission_set_arn(
                        each_perm_set_name, current_aws_permission_sets)
                    if not permission_set_arn:
                        continue
                    # Remove matched assignment from list
                    if each_assignment['PrincipalId'] == global_group_id and each_assignment["PermissionSetArn"] == permission_set_arn:
                        remove_list.append(each_assignment)
        except Exception as error:
            error_message = f"Exception while detecting drift: {error}"
            log_and_append_error(error_message)
    for each_assignment in check_list:
        try:
            for target_mapping in target_file_contents:
                account_id = each_assignment['AccountId']
                target_accounts = []

                for target in target_mapping['TargetAccountid']:
                    if target.startswith('ou:'):
                        ou_name = target.split(':')[1].strip()
                        ou_accounts = get_accounts_in_ou(ou_name)
                        target_accounts.extend(ou_accounts)
                    else:
                        if target.startswith('name:'):
                            acct_name = target.split(':')[1].strip()
                            resolved_id = get_account_id_by_name(acct_name)
                            if resolved_id:
                                target_accounts.append(resolved_id)
                        else:
                            target_accounts.append(target)

                if account_id in target_accounts:
                    for each_perm_set_name in target_mapping['PermissionSetName']:
                        permission_set_arn = get_permission_set_arn(
                            each_perm_set_name, current_aws_permission_sets)
                        if not permission_set_arn:
                            continue
                        target_group_id = get_valid_group_id(
                            target_mapping['TargetGroupName'])
                        if not target_group_id:
                            continue
                        if each_assignment['PrincipalId'] == target_group_id and each_assignment['PermissionSetArn'] == permission_set_arn:
                            remove_list.append(each_assignment)
        except Exception as error:
            error_message = f"Exception while detecting drift: {error}"
            log_and_append_error(error_message)
    for item in remove_list:
        try:
            check_list.remove(item)
        except ValueError:
            logger.warning(
                f'Remove list item {item} not in check list. Skipping...')
    if len(check_list) == 0:
        logger.info(
            "IAM Identity Center assignments has been applied. No drift was found within current assignments :)")
    else:
        for delta_assignment in check_list:
            try:
                logger.warning(f"Assignment with drift: {delta_assignment}")
                delete_user_assignment = ic_admin.delete_account_assignment(
                    InstanceArn=ic_instance_arn,
                    TargetId=delta_assignment['AccountId'],
                    TargetType='AWS_ACCOUNT',
                    PermissionSetArn=delta_assignment['PermissionSetArn'],
                    PrincipalType='GROUP',
                    PrincipalId=delta_assignment['PrincipalId']
                )
                if 'AccountAssignmentDeletionStatus' in delete_user_assignment and delete_user_assignment['AccountAssignmentDeletionStatus'].get('RequestId'):
                    request_id = delete_user_assignment['AccountAssignmentDeletionStatus']['RequestId']
                    complete = False
                    while not complete:
                        status_response = ic_admin.describe_account_assignment_deletion_status(
                            InstanceArn=ic_instance_arn,
                            AccountAssignmentDeletionRequestId=request_id
                        )
                        current_status = status_response['AccountAssignmentDeletionStatus']['Status']
                        if current_status == 'IN_PROGRESS':
                            logger.info('Delete assignment in progress...')
                            sleep(1)
                        elif current_status == 'SUCCEEDED':
                            complete = True
                            logger.info(
                                "Delete assignment completed successfully")
                            sleep(0.5)
                        elif current_status == 'FAILED':
                            complete = True
                            failure_reason = status_response['AccountAssignmentDeletionStatus'].get(
                                'FailureReason', 'Unknown')
                            log_and_append_error(
                                f"Delete assignment failed for permission set {delta_assignment['PermissionSetName']} for account {delta_assignment['AccountId']}. Reason:{failure_reason}")
                            sleep(0.5)
                group_name = get_group_name_from_id(
                    delta_assignment['PrincipalId'])
                if not group_name:
                    group_name = delta_assignment['PrincipalId']
                perm_set_name = get_perm_set_name_from_arn(
                    delta_assignment['PermissionSetArn'])
                if not perm_set_name:
                    perm_set_name = delta_assignment['PermissionSetArn']
                logger.warning(
                    f"Warning. Drift has been detected and removing. \
                        Principal: {group_name}, \
                            Permission Set: {perm_set_name}, \
                                Account Id: {delta_assignment['AccountId']}")
                logger.debug(
                    f"Warning. Drift has been detected and removing. \
                        PrincipalId: {delta_assignment['PrincipalId']} (Group Name: {group_name}), \
                            Permission Set Arn: {delta_assignment['PermissionSetArn']} (Permission Set Name: {perm_set_name}), \
                                Account Id: {delta_assignment['AccountId']}, \
                                    Delete Assignment: {delete_user_assignment}")
            except Exception as error:
                error_message = f"Exception while deleting account from drift: {error}"
                log_and_append_error(error_message)


def get_global_mapping_contents(bucketname, global_mapping_file):
    """Get global mapping info from JSON files"""
    try:
        logger.info("Getting global mapping info from JSON files.")
        filedata = s3client.get_object(
            Bucket=bucketname,
            Key=global_mapping_file
        )
        content = filedata['Body']
        json_object = json.loads(content.read())

    except Exception as error:
        error_message = f"Cannot get global mapping information. \
            Did you upload the global mapping file in correct JSON format? {error}"
        log_and_append_error(error_message)
        if errors:
            error_message = f'Errors encountered during processing: {errors}'
        sys.exit(1)
    return json_object


def get_target_mapping_contents(bucketname, target_mapping_file):
    """Get target mapping info from uploaded JSON files"""
    try:
        logger.info("Getting target mapping info from JSON files")
        filedata = s3client.get_object(
            Bucket=bucketname,
            Key=target_mapping_file
        )
        content = filedata['Body']
        json_object = json.loads(content.read())

    except Exception as error:
        error_message = f"Cannot get target mapping information.\
            Did you upload the target mapping file in correct JSON format? {error}"
        log_and_append_error(error_message)
        if errors:
            error_message = f'Errors encountered during processing: {errors}'
        sys.exit(1)
    return json_object


def validate_mapping_file_structure(permission_set_file, group_type):
    """Validate the structure of the permission set mapping file."""
    logger.info(f"Validating file structure for {group_type} mapping")

    required_keys = {
        "PermissionSetName": list
    }

    if group_type == 'global':
        group_key = 'GlobalGroupName'
        target_accountid_type = str
    elif group_type == 'target':
        group_key = 'TargetGroupName'
        target_accountid_type = list
    else:
        raise ValueError("Invalid group type. Must be 'global' or 'target'.")

    if not isinstance(permission_set_file, list):
        raise TypeError("The mapping file must be a list")

    for idx, permission_set in enumerate(permission_set_file):
        if not isinstance(permission_set, dict):
            raise TypeError(
                f"Each item in the mapping file must be a dictionary. Item at index {idx} is not a dictionary.")

        if group_key not in permission_set:
            raise ValueError(
                f"Missing required key: '{group_key}' in mapping file at index {idx}")

        if not isinstance(permission_set[group_key], str):
            raise TypeError(
                f"Key '{group_key}' is not of expected type str at index {idx}")

        for key, expected_type in required_keys.items():
            if key not in permission_set:
                raise ValueError(
                    f"Missing required key: {key} in permission set at index {idx}")
            if not isinstance(permission_set[key], expected_type):
                raise TypeError(
                    f"Key '{key}' is not of expected type {expected_type.__name__} in permission set at index {idx}")

        if "TargetAccountid" not in permission_set:
            raise ValueError(
                f"Missing required key: 'TargetAccountid' in mapping at index {idx}")

        if not isinstance(permission_set["TargetAccountid"], target_accountid_type):
            raise TypeError(
                f"'TargetAccountid' must be of type {target_accountid_type.__name__} in mapping file at index {idx}")

        if not all(isinstance(item, str) for item in permission_set["PermissionSetName"]):
            raise ValueError(
                f"All items in 'PermissionSetName' must be strings in permission sets at index {idx}")

        if group_type == "target" and not all(isinstance(item, str) for item in permission_set["TargetAccountid"]):
            raise ValueError(
                f"All items in the list 'TargetAccountid' must be strings in account IDs at index {idx}")


def global_group_array_mapping(acct_list, global_file_contents,
                               current_aws_permission_sets):
    """Create global group mapping assignments"""
    logger.info('Starting global mapping assignments')
    group_type = 'global'

    for acct in acct_list:
        if acct['Status'] in ["SUSPENDED", "PENDING_CLOSURE"]:
            logger.info(
                f"Account ID: {acct['Id']} is in {acct['Status']} status and will be skipped.")

    # Validate the structure of the global file content
    try:
        validate_mapping_file_structure(global_file_contents, group_type)
    except (ValueError, TypeError) as e:
        error_message = f"Validation error in global file contents: {e}"
        log_and_append_error(error_message)
        return

    logger.info("Starting global group assignment")

    if global_file_contents:
        for account in acct_list:
            if account['Status'] not in ["SUSPENDED", "PENDING_CLOSURE"]:
                for index, mapping in enumerate(global_file_contents):
                    if mapping['TargetAccountid'].upper() == "GLOBAL":
                        try:
                            logger.debug(
                                "Processing mapping: %s for account: %s", mapping, account)
                            for each_perm_set_name in mapping['PermissionSetName']:
                                permission_set_arn = get_permission_set_arn(
                                    each_perm_set_name, current_aws_permission_sets)
                                if not permission_set_arn:
                                    continue
                                group_id = get_valid_group_id(
                                    mapping['GlobalGroupName'])
                                if not group_id:
                                    continue

                                assignment_response = ic_admin.create_account_assignment(
                                    InstanceArn=ic_instance_arn,
                                    TargetId=str(account['Id']),
                                    TargetType='AWS_ACCOUNT',
                                    PrincipalType='GROUP',
                                    PermissionSetArn=permission_set_arn,
                                    PrincipalId=group_id
                                )

                                if 'AccountAssignmentCreationStatus' in assignment_response and assignment_response['AccountAssignmentCreationStatus'].get('RequestId'):
                                    request_id = assignment_response['AccountAssignmentCreationStatus']['RequestId']
                                    complete = False
                                    while not complete:
                                        status_response = ic_admin.describe_account_assignment_creation_status(
                                            InstanceArn=ic_instance_arn,
                                            AccountAssignmentCreationRequestId=request_id
                                        )
                                        current_status = status_response['AccountAssignmentCreationStatus']['Status']
                                        if current_status == 'IN_PROGRESS':
                                            logger.info(
                                                'Create assignment in progress...')
                                            sleep(1)
                                        elif current_status == 'SUCCEEDED':
                                            complete = True
                                            logger.info(
                                                "Create assignment completed successfully")
                                            logger.info("Performed global IAM Identity Center group assigment on \
                                            account: %s, \
                                            Group: %s, \
                                            Permission Set: %s", account['Id'], mapping['GlobalGroupName'], mapping['PermissionSetName'])
                                            sleep(0.5)
                                        elif current_status == 'FAILED':
                                            complete = True
                                            failure_reason = status_response['AccountAssignmentCreationStatus'].get(
                                                'FailureReason', 'Unknown')
                                            log_and_append_error(
                                                f"Create assignment failed for permission set {mapping['PermissionSetName']} for account {account['Id']} . Reason: {failure_reason}")
                                            sleep(0.5)

                                logger.debug("Performed global IAM Identity Center group assigment on \
                                            account: %s, \
                                            Group: %s, \
                                            Permission Set: %s, \
                                            Response: %s", account['Id'], mapping['GlobalGroupName'], mapping['PermissionSetName'], assignment_response)

                        except ic_admin.exceptions.ConflictException as error:
                            logger.info("%s.The same create account assignment process has been \
                                        started in another invocation skipping.", error)
                            sleep(0.5)
                            continue
                        except ClientError as error:
                            error_message = f"Create global account assignment failed: {error}"
                            log_and_append_error(error_message)
                            continue
                        except Exception as error:
                            error_message = f'Error occurred: {error}'
                            log_and_append_error(error_message)
                            continue
                    else:
                        logger.warning(
                            "Incorrect TargetAccount value at index %d: %s. Skipping this assignment.", index, mapping)
    else:
        logger.info(
            "No global mapping information is loaded in existing files.")


def target_group_array_mapping(acct_list, target_file_contents,
                               current_aws_permission_sets):
    """Create target group mapping assignments"""
    logger.info('Starting target mapping assignments')

    for acct in acct_list:
        if acct['Status'] in ["SUSPENDED", "PENDING_CLOSURE"]:
            logger.info(
                f"Account ID: {acct['Id']} is in {acct['Status']} status and will be skipped.")

    if delegated == 'true':
        target_accounts = [
            acct for acct in acct_list if (acct['Id'] != management_account_id and acct['Status'] not in ["SUSPENDED", "PENDING_CLOSURE"])
        ]
    else:
        target_accounts = [
            acct for acct in acct_list if acct['Status'] not in ["SUSPENDED", "PENDING_CLOSURE"]
        ]

    group_type = 'target'

    # Validate the structure of the target file content
    try:
        validate_mapping_file_structure(target_file_contents, group_type)
    except (ValueError, TypeError) as e:
        error_message = f"Validation error in target file contents: {e}"
        log_and_append_error(error_message)
        return

    logger.info("Starting target group assignement")
    if target_file_contents:
        try:
            for mapping in target_file_contents:
                mapping_target_accounts = []

                for target in mapping['TargetAccountid']:
                    if target.startswith('name:'):
                        acct_name = target.split(':')[1].strip()
                        account_id = get_account_id_by_name(acct_name)
                        if account_id:
                            for acct in target_accounts:
                                if acct['Id'] == account_id and acct['Status'] not in ["SUSPENDED", "PENDING_CLOSURE"]:
                                    mapping_target_accounts.append(account_id)
                                    break
                        else:
                            logger.warning(
                                f"Could not resolve account name: {acct_name}")
                    elif target.startswith('ou:'):
                        ou_name = target.split(':')[1].strip()
                        ou_account_ids = get_accounts_in_ou(ou_name)
                        if ou_account_ids:
                            for account_id in ou_account_ids:
                                for acct in target_accounts:
                                    if acct['Id'] == account_id and acct['Status'] not in ["SUSPENDED", "PENDING_CLOSURE"]:
                                        mapping_target_accounts.append(
                                            account_id)
                                        break
                        else:
                            logger.warning(
                                f"No accounts found in OU: {ou_name}")
                    else:
                        for acct in target_accounts:
                            if acct['Id'] == target and acct['Status'] not in ["SUSPENDED", "PENDING_CLOSURE"]:
                                mapping_target_accounts.append(target)
                                break

                # Remove duplicates
                mapping_target_accounts = list(
                    dict.fromkeys(mapping_target_accounts))

                for each_perm_set_name in mapping['PermissionSetName']:
                    for target_account_id in mapping_target_accounts:
                        try:
                            permission_set_arn = get_permission_set_arn(
                                each_perm_set_name, current_aws_permission_sets)
                            if not permission_set_arn:
                                continue

                            group_id = get_valid_group_id(
                                mapping['TargetGroupName'])
                            if not group_id:
                                continue

                            assignment_response = ic_admin.create_account_assignment(
                                InstanceArn=ic_instance_arn,
                                TargetId=str(target_account_id),
                                TargetType='AWS_ACCOUNT',
                                PrincipalType='GROUP',
                                PermissionSetArn=permission_set_arn,
                                PrincipalId=group_id
                            )

                            if 'AccountAssignmentCreationStatus' in assignment_response and assignment_response['AccountAssignmentCreationStatus'].get('RequestId'):
                                request_id = assignment_response['AccountAssignmentCreationStatus']['RequestId']
                                complete = False
                                while not complete:
                                    status_response = ic_admin.describe_account_assignment_creation_status(
                                        InstanceArn=ic_instance_arn,
                                        AccountAssignmentCreationRequestId=request_id
                                    )
                                    current_status = status_response['AccountAssignmentCreationStatus']['Status']

                                    if current_status == 'IN_PROGRESS':
                                        logger.info(
                                            'Create assignment in progress...')
                                        sleep(1)
                                    elif current_status == 'SUCCEEDED':
                                        complete = True
                                        logger.info(
                                            "Create assignment completed successfully")
                                        sleep(0.5)
                                        logger.info("Performed target IAM Identity Center group assigment on account: %s, \
                                                    Group: %s,  \
                                                    Permission Set: %s",
                                                    target_account_id, mapping['TargetGroupName'], each_perm_set_name)
                                    elif current_status == 'FAILED':
                                        complete = True
                                        failure_reason = status_response['AccountAssignmentCreationStatus'].get(
                                            'FailureReason', 'Unknown')
                                        error_message = f"Create assignment failed for permission set {mapping['PermissionSetName']} for account {target_account_id}. Reason: {failure_reason}"
                                        log_and_append_error(error_message)
                                        complete = True
                                        sleep(0.5)
                            logger.debug("Performed target IAM Identity Center group assigment on \
                                            account: %s, \
                                            Group: %s, \
                                            Permission Set: %s, \
                                            Response: %s", target_account_id, mapping['TargetGroupName'], each_perm_set_name, assignment_response)

                        except ic_admin.exceptions.ConflictException as error:
                            logger.info(
                                "Assignment process already started in another invocation, skipping. (%s)", error)
                            sleep(0.5)
                            continue

                        except ClientError as error:
                            error_message = f"Failed to create assignment for account {target_account_id}: {error}"
                            log_and_append_error(error_message)
                            continue

                        except Exception as error:
                            error_message = f"Unexpected error for account {target_account_id}: {error}"
                            log_and_append_error(error_message)
                            continue

        except ic_admin.exceptions.ConflictException as error:
            logger.info("%s. The same create account assignment process has been \
                        started in another invocation skipping.", error)
            sleep(0.5)
        except ClientError as error:
            error_message = f"Create target account assignment failed: {error}"
            log_and_append_error(error_message)
        except Exception as error:
            error_message = f'Error occurred: {error}'
            log_and_append_error(error_message)

    else:
        logger.info(
            "No target mapping information is loaded in existing files.")


def get_all_permission_sets():
    """List all the permission sets for the IAM Identity Center ARN"""
    permission_set_name_and_arn = {}
    try:
        response = ic_admin.list_permission_sets(
            InstanceArn=ic_instance_arn,
            MaxResults=100
        )
        ic_permission_sets = response['PermissionSets']
        while 'NextToken' in response:
            response = ic_admin.list_permission_sets(
                InstanceArn=ic_instance_arn,
                MaxResults=100,
                NextToken=response['NextToken']
            )
            ic_permission_sets += response['PermissionSets']
        global skipped_perm_set
        skipped_perm_set.clear()
        for perm_set_arn in ic_permission_sets:
            describe_perm_set = ic_admin.describe_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn
            )
            sleep(0.1)
            perm_set_name = describe_perm_set['PermissionSet']['Name']
            perm_set_arn = describe_perm_set['PermissionSet']['PermissionSetArn']
            list_tags = ic_admin.list_tags_for_resource(
                InstanceArn=ic_instance_arn,
                ResourceArn=perm_set_arn
            )
            sleep(0.1)
            tags = list_tags['Tags']
            while 'NextToken' in list_tags:
                list_tags = ic_admin.list_tags_for_resource(
                    InstanceArn=ic_instance_arn,
                    ResourceArn=perm_set_arn,
                    NextToken=list_tags['NextToken']
                )
                tags += list_tags['Tags']
            control_tower_managed = False
            for tag in tags:
                if tag['Key'] == 'managedBy' and tag['Value'] == 'ControlTower':
                    control_tower_managed = True
                    break
            if control_tower_managed == True:
                skipped_perm_set.update({perm_set_arn: perm_set_name})
                # Ignore permission set if managed by Control Tower. Requires users to tag Control Tower managed permission sets before running the pipeline.
                continue
            permission_set_name_and_arn[perm_set_name] = {'Arn': perm_set_arn}
            logger.debug(
                f"Skipped Permission Set Name and ARN: {skipped_perm_set}")

    except ClientError as error:
        error_message = f"List permission sets failed: {error}"
        log_and_append_error(error_message)
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)

    return permission_set_name_and_arn


def get_all_permission_sets_if_delegate():
    """List all the permission sets for the IAM Identity Center ARN"""
    permission_set_name_and_arn = {}
    try:
        logger.debug(f'Trying to list permission sets')
        response = ic_admin.list_permission_sets(
            InstanceArn=ic_instance_arn,
            MaxResults=100
        )
        ic_permission_sets = response['PermissionSets']
        while 'NextToken' in response:
            response = ic_admin.list_permission_sets(
                InstanceArn=ic_instance_arn,
                MaxResults=100,
                NextToken=response['NextToken']
            )
            ic_permission_sets += response['PermissionSets']

        global skipped_perm_set
        skipped_perm_set.clear()
        for perm_set_arn in ic_permission_sets:
            logger.debug(f'Describing permission set: {perm_set_arn}')
            try:
                describe_perm_set = ic_admin.describe_permission_set(
                    InstanceArn=ic_instance_arn,
                    PermissionSetArn=perm_set_arn
                )
            except ic_admin.exceptions.ResourceNotFoundException as error:
                error_message = f'Permission set {perm_set_name} not found: {error}'
                log_and_append_error(error_message)
                continue
            sleep(0.1)
            perm_set_name = describe_perm_set['PermissionSet']['Name']
            perm_set_arn = describe_perm_set['PermissionSet']['PermissionSetArn']
            list_accounts_for_provisioned_perm_set = ic_admin.list_accounts_for_provisioned_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                MaxResults=100,
            )
            accounts_for_perm_set = list_accounts_for_provisioned_perm_set['AccountIds']
            sleep(0.1)
            while 'NextToken' in list_accounts_for_provisioned_perm_set:
                list_accounts_for_provisioned_perm_set = ic_admin.list_accounts_for_provisioned_permission_set(
                    InstanceArn=ic_instance_arn,
                    PermissionSetArn=perm_set_arn,
                    MaxResults=100,
                    NextToken=list_accounts_for_provisioned_perm_set['NextToken']
                )
                sleep(0.1)
                accounts_for_perm_set += list_accounts_for_provisioned_perm_set['AccountIds']
            logger.debug(
                f"Accounts for permission set {perm_set_arn} is {accounts_for_perm_set}")
            if management_account_id in accounts_for_perm_set:
                skipped_perm_set.update({perm_set_arn: perm_set_name})
                continue
            permission_set_name_and_arn[perm_set_name] = {'Arn': perm_set_arn}
            logger.debug("%s", permission_set_name_and_arn)

    except ClientError as error:
        error_message = f"List permission sets failed: {error}"
        log_and_append_error(error_message)
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)
    logger.info(f"Skipped Permission Set Name and ARN: {skipped_perm_set}")
    return permission_set_name_and_arn


def get_groupid(group_display_name):
    """Get the all the IAM Identity Center group names and ids"""
    try:
        response = identitystore_client.get_group_id(
            IdentityStoreId=identity_store_id,
            AlternateIdentifier={
                'UniqueAttribute':
                {
                    'AttributePath': 'DisplayName',
                    'AttributeValue': str(group_display_name)
                }
            }
        )
        if response['GroupId'] == []:
            error_message = f'Group "{group_display_name}" does not exist.'
            log_and_append_error(error_message)
            group_id = None
        else:
            group_id = response['GroupId']

    except ClientError as error:
        error_message = f'ClientError while getting group ids: {error}'
        log_and_append_error(error_message)
        raise
    except identitystore_client.exceptions.ResourceNotFoundException as error:
        error_message = f'Group "{group_display_name}" not found in Identity Center: {error}'
        log_and_append_error(error_message)
        raise
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)
        raise
    return group_id


def get_group_name_from_id(group_id):
    """Get the IAM Identity Center group names from ids"""
    try:
        response = identitystore_client.describe_group(
            IdentityStoreId=identity_store_id,
            GroupId=group_id
        )
        if response['GroupId'] == []:
            error_message = f'Group "{group_id}" does not exist.'
            log_and_append_error(error_message)
            group_name = None
        else:
            group_name = response['DisplayName']

    except ClientError as error:
        error_message = f'ClientError while getting group name: {error}'
        log_and_append_error(error_message)
        raise
    except identitystore_client.exceptions.ResourceNotFoundException as error:
        error_message = f'Group "{group_id}" not found in Identity Center: {error}'
        log_and_append_error(error_message)
        raise
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)
        raise
    return group_name


def get_perm_set_name_from_arn(perm_set_arn):
    """Get the IAM Identity Center permission set names from arns"""
    try:
        response = ic_admin.describe_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )
        if response['PermissionSet']['PermissionSetArn'] == '':
            error_message = f'Permission Set "{perm_set_arn}" does not exist.'
            log_and_append_error(error_message)
            perm_set_name = None
        else:
            perm_set_name = response['PermissionSet']['Name']

    except ClientError as error:
        error_message = f'ClientError while getting permission set name: {error}'
        log_and_append_error(error_message)
        raise
    except identitystore_client.exceptions.ResourceNotFoundException as error:
        error_message = f'Permission Set "{perm_set_arn}" not found in Identity Center: {error}'
        log_and_append_error(error_message)
        raise
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)
        raise
    return perm_set_name


def get_org_accounts():
    """Get all account ids from the current AWS Organizations"""
    try:
        logger.info('Getting accounts from Organization')
        response = orgs_client.list_accounts()
        org_accts = response['Accounts']
        while 'NextToken' in response:
            response = orgs_client.list_accounts(
                NextToken=response['NextToken']
            )
            org_accts += response['Accounts']
    except ClientError as error:
        error_message = f'ClientError while listing account Ids in organization: {error}'
        log_and_append_error(error_message)
        org_accts = None
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)
        org_accts = None
    logger.debug(f"Retrieved Organization account IDs: {org_accts}")
    return org_accts


def get_org_accounts_if_delegate():
    """Get all account ids from the current AWS Organizations"""
    try:
        logger.info('Getting accounts from Organization')
        response = orgs_client.list_accounts()
        org_accts = response['Accounts']
        while 'NextToken' in response:
            response = orgs_client.list_accounts(
                NextToken=response['NextToken']
            )
            org_accts += response['Accounts']
    except ClientError as error:
        error_message = f'ClientError during delegated listing accounts: {error}'
        log_and_append_error(error_message)
        org_accts = None
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)
        org_accts = None

    org_accts = [acct for acct in org_accts if acct['Id']
                 != management_account_id]
    logger.debug(f"Retrieved Organization account IDs: {org_accts}")
    return org_accts


def main(event=None):
    """
    Main function to handle Pipeline triggered and EventBridge triggered events for assignment automation.

    Args:
        event (dict, optional): Event payload if triggered by EventBridge Rules.
        Defaults to None.
    """
    logger.debug(f"Delegated: {delegated}")
    global errors
    errors = []

    try:
        if build_initiator.startswith('rule'):
            if event == 'AWS API Call via CloudTrail':
                event_id = os.getenv("EVENT_ID")
                event_source = os.getenv("EVENT_SOURCE")
                event_name = os.getenv("EVENT_NAME")
                user_identity = os.getenv("USER_IDENTITY")
                logger.info(f'This build is triggered by EventBridge with the following parameters:\
                            Event Type: {event}\
                                Event Name: {event_name}\
                                    CloudTrail Event ID: {event_id}\
                                        Event Source: {event_source}\
                                            Performed by user: {user_identity}')
                if event_source == 'aws.sso-directory':
                    logger.warning(f'This event is generated from source {event_source} and cannot be automatically reverted.\
                                This build will still run to baseline Permission Sets and assignments.\
                                However, please confirm that the initiator event {event_name} is legitimate. If not, revert it manually')
            elif event == 'Scheduled Event':
                event_source = os.getenv("EVENT_SOURCE")
                logger.info(f'This build is triggered by EventBridge Scheduler running every 12 hours with the following parameters\
                            Event Type: {event}\
                                Event Source: {event_source}')
            elif event == 'AWS Service Event via CloudTrail':
                event_id = os.getenv("EVENT_ID")
                event_source = os.getenv("EVENT_SOURCE")
                event_name = os.getenv("EVENT_NAME")
                event_create_account_id = os.getenv("EVENT_CREATE_ACCOUNT_ID")
                event_joined_account_id = os.getenv("EVENT_JOINED_ACCOUNT_ID")
                if event_create_account_id:
                    event_account_id = event_create_account_id
                elif event_joined_account_id:
                    event_account_id = event_joined_account_id
                logger.info(f'This build is triggered by EventBridge with the following parameters:\
                            Event Type: {event}\
                                Event Name: {event_name}\
                                    CloudTrail Event ID: {event_id}\
                                        Event Source: {event_source}\
                                            New AWS account ID: {event_account_id}')
        elif build_initiator.startswith('codepipeline'):
            logger.info(f'This build is triggered by Pipeline with the following parameters:\
                        Pipeline Name: {build_initiator}\
                            Pipeline Execution ID: {pipeline_execution_id}\
                                Commit ID: {commit_id}.')
        else:
            logger.info(
                f"This build is triggered by {build_initiator} either manually or by an unknown source")

        logger.info("Starting the Process...")
        if delegated == 'true':
            acct_list = get_org_accounts_if_delegate()
        else:
            acct_list = get_org_accounts()
        # Check if Source files exist.
        logger.info("Loaded mapping information from the files in s3...")
        global_file_contents = get_global_mapping_contents(
            ic_bucket_name, global_mapping_file_name)
        target_file_contents = get_target_mapping_contents(
            ic_bucket_name, target_mapping_file_name)
        logger.info("Loaded mapping information from the files in s3...")
        # Get current permission set info.
        if delegated == "true":
            current_aws_permission_sets = get_all_permission_sets_if_delegate()
            logger.debug(
                "INFO: Admin delegated. Running in delegated admin account.")
        else:
            current_aws_permission_sets = get_all_permission_sets()
            logger.debug(
                "INFO: Admin NOT delegated. Running in Management account.")
        if not current_aws_permission_sets:
            error_message = "Cannot load existing Permission Sets from AWS IAM Identity Center!"
            log_and_append_error(error_message)
            if errors:
                error_message = f'Errors encountered during processing: {errors}'
            sys.exit(1)
        else:
            logger.info("The current permision sets in this account:%s",
                        current_aws_permission_sets)
        # Use S3 mapping files(sycned from source) as the only source of truth.
        global_group_array_mapping(
            acct_list, global_file_contents, current_aws_permission_sets)
        target_group_array_mapping(
            acct_list, target_file_contents, current_aws_permission_sets)
        all_assignments = list_all_current_account_assignment(
            acct_list, current_aws_permission_sets)
        drift_detect_update(all_assignments, global_file_contents,
                            target_file_contents, current_aws_permission_sets)
        if errors:
            logger.error(f'All Errors during execution: {errors}')
            logger.info("Execution is complete.")
            logger.info(f'Codebuild logs contain combined logs for the build project.\
                If you wish to view the logs for just the auto-assignment function, you can check out CloudWatch logs: "{assignment_automation_log_group}/[buildId]-{build_id}"\
                    https://{runtime_region}.console.aws.amazon.com/cloudwatch/home?region={runtime_region}#logsV2:log-groups/log-group/{assignment_automation_log_group}/log-events/[buildId]-{build_id}')
            sys.exit(1)
        else:
            logger.info("Execution is complete.")
            logger.info(f'Codebuild logs contain combined logs for the build project.\
                If you wish to view the logs for just the auto-assignment function, you can check out CloudWatch logs: "{assignment_automation_log_group}/[buildId]-{build_id}"\
                    https://{runtime_region}.console.aws.amazon.com/cloudwatch/home?region={runtime_region}#logsV2:log-groups/log-group/{assignment_automation_log_group}/log-events/[buildId]-{build_id}')

    except Exception as error:
        error_message = f'Exception caught: {error}'
        log_and_append_error(error_message)
        if errors:
            logger.error(f'Errors during execution: {errors}')
        sys.exit(1)


if __name__ == "__main__":

    logger.info(f'Codebuild logs contain combined logs for the build project.\
                If you wish to view the logs for just the auto-assignment function, you can check out CloudWatch logs: "{assignment_automation_log_group}/[buildId]-{build_id}"\
                    https://{runtime_region}.console.aws.amazon.com/cloudwatch/home?region={runtime_region}#logsV2:log-groups/log-group/{assignment_automation_log_group}/log-events/[buildId]-{build_id}')
    main(event)
    # Flush and close watchtower
    watchtower_handler.flush()
    watchtower_handler.close()
