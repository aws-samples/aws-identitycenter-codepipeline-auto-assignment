"""Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved"""
# pylint: disable=C0301
# pylint: disable=W1202,W0703
# pylint: disable=E0401
import os
import json
import logging
import re
import sys
from time import sleep
import time
import urllib.parse
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config
import watchtower
from typing import List, Dict, Union, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
# from functools import lru_cache
# from profilehooks import profile

ASSIGNMENT_WORKERS = 10  # For Create/DeleteAccountAssignment
GENERAL_WORKERS = 20     # For read/list operations
RETRY_BASE_DELAY = 1     # Base delay for exponential backoff in seconds


AWS_CONFIG = Config(
    retries=dict(
        max_attempts=100,
        mode='adaptive'
    ),
    max_pool_connections=ASSIGNMENT_WORKERS + GENERAL_WORKERS
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
logged_permission_sets = {}


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

CACHE_TTL = 1800  # 30 minutes

# Cache storage


class CacheManager:
    def __init__(self):
        self._cache = {}
        self._timestamps = {}

    def get(self, key):
        if key in self._cache and time.time() - self._timestamps.get(key, 0) < CACHE_TTL:
            return self._cache[key]
        return None

    def set(self, key, value):
        self._cache[key] = value
        self._timestamps[key] = time.time()


cache = CacheManager()


def execute_with_retry(func, *args, **kwargs):
    """Helper for API calls with exponential backoff and jitter"""
    max_attempts = 5
    for attempt in range(max_attempts):
        try:
            return func(*args, **kwargs)
        except (ClientError, ic_admin.exceptions.ConflictException) as error:
            if attempt == max_attempts - 1:
                raise
            sleep_time = RETRY_BASE_DELAY * (2 ** attempt) + random.uniform(0, 1)
            logger.warning(
                f"Retrying {func.__name__} in {sleep_time:.2f}s (attempt {attempt + 1})")
            sleep(sleep_time)
        except Exception as error:
            log_and_append_error(
                f"Unexpected error in {func.__name__}: {str(error)}")
            raise

def get_valid_group_id(group_name):
    cached = cache.get(f"group_{group_name}")
    if cached:
        return cached
    try:
        logger.debug(f"Getting group ID for group name: {group_name}")
        response = identitystore_client.get_group_id(
            IdentityStoreId=identity_store_id,
            AlternateIdentifier={
                'UniqueAttribute':
                {
                    'AttributePath': 'DisplayName',
                    'AttributeValue': str(group_name)
                }
            }
        )
        group_id = response['GroupId']
        cache.set(f"group_{group_name}", group_id)
        return group_id

    except identitystore_client.exceptions.ResourceNotFoundException:
        log_and_append_error(
            f'Group "{group_name}" not found in Identity Center')
        return None
    except Exception as error:
        log_and_append_error(f'Error getting group ID: {error}')
        return None


def parse_target_field(target_data: List[Union[Dict[str, List[str]], str]], field_name: str = None) -> List[str]:
    """
    Parse the target field (Target or TargetAccountid) that supports OrganizationalUnits and accounts.
    """
    resolved_accounts = set()
    logger.debug(f'Parsing {field_name if field_name else "target"} field')

    for target in target_data:
        if isinstance(target, str):
            # Direct account ID
            resolved_accounts.add(target)
        elif isinstance(target, dict):
            # Process organizational units
            if 'OrganizationalUnits' in target:
                for ou_path in target['OrganizationalUnits']:
                    accounts = get_accounts_in_ou(ou_path)
                    resolved_accounts.update(accounts)

            # Process account names/IDs
            if 'Accounts' in target:
                for account in target['Accounts']:
                    # Verify account is an ID (12 digit number)
                    if re.match(r'^\d{12}$', account):
                        resolved_accounts.add(account)
                    else:
                        account_id = get_account_id_by_name(account)
                        if account_id:
                            resolved_accounts.add(account_id)
                        else:
                            logger.warning(
                                f"Could not resolve account name: {account}")

    return list(resolved_accounts)

def get_permission_set_arn(permission_set_name, current_aws_permission_sets):
    """Get permission set by name"""
    cache_key = f'ps_{permission_set_name}'
    cached = cache.get(cache_key)
    if cached:
        return cached
    logger.debug(f"Looking up permission set ARN for: {permission_set_name}")
    try:
        arn = current_aws_permission_sets[permission_set_name]['Arn']
        logger.debug(
            f"Found ARN for permission set {permission_set_name}: {arn}")
        cache.set(cache_key, arn)
        return arn
    except KeyError as error:
        # Check if permission set exists in skipped permission set list
        skipped = False
        for perm_set_arn, perm_set_name in skipped_perm_set.items():
            if permission_set_name == perm_set_name:
                skipped = True
                if permission_set_name not in logged_permission_sets:
                    logged_permission_sets[permission_set_name] = True
                    logger.warning('WARNING: Permission set %s already exists and is either managed by Control Tower, or provisioned in the management account. \
                                   Please create a different permission set that will not be provisioned in the management account or not managed by Control Tower.', permission_set_name)
                break
        if not skipped:
            error_message = f'PermissionSet: {permission_set_name} not found. Skipping assignment.'
            logger.warning(error_message)
        return None


def get_account_id_by_name(account_name):
    """Get AWS account ID from account name"""
    cache_key = f"account_name_{account_name}"
    cached = cache.get(cache_key)
    if cached:
        return cached
    logger.debug(f"Looking up account ID for account name: {account_name}")
    account_id = None
    try:
        accounts = get_org_accounts()
        for account in accounts:
            if account['Name'] == account_name:
                account_id = account['Id']
                cache.set(cache_key, account_id)
                return account_id
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

def find_ou_id(parent_id, ou_path):
    """Find OU ID by path"""
    try:
        path_components = [p for p in ou_path.split('/') if p]
        if not path_components:
            return None
        paginator = orgs_client.get_paginator(
            'list_organizational_units_for_parent')

        for page in paginator.paginate(ParentId=parent_id):
            for ou in page['OrganizationalUnits']:
                current_name = path_components[0]
                if ou['Name'] == current_name:
                    if len(path_components) == 1:
                        return ou['Id']
                    remaining_path = '/'.join(path_components[1:])
                    nested_ou_id = find_ou_id(ou['Id'], remaining_path)
                    if nested_ou_id:
                        return nested_ou_id
        return None

    except orgs_client.exceptions.ParentNotFoundException:
        return None

def get_accounts_in_ou(ou_path):
    """Get list of account IDs in an organizational unit by OU path, including nested OUs."""
    cached = cache.get(f"ou_{ou_path}")
    if cached:
        return cached
    accounts = []
    try:
        root_response = orgs_client.list_roots()
        root_id = root_response['Roots'][0]['Id']
        ou_id = find_ou_id(root_id, ou_path)

        if ou_id:
            accounts = get_all_accounts_in_ou(ou_id)
            cache.set(f"ou_{ou_path}", accounts)
    except ClientError as error:
        log_and_append_error(
            f"Error getting accounts for OU {ou_path}: {error}")
        return accounts
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)
        return accounts

    return accounts


def get_all_accounts_in_ou(parent_id):
    """Recursively get all accounts in an OU and its child OUs"""
    cached = cache.get(f"ou_accounts_{parent_id}")
    if cached:
        return cached
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
    cache.set(f"ou_accounts_{parent_id}", ou_accounts)
    return ou_accounts


def list_all_current_account_assignment(acct_list, current_aws_permission_sets):
    """List all the current account assignments information"""
    all_assignments = []
    logger.info("Scanning current group assignments. This may take some time...")
    for each_perm_set_name in current_aws_permission_sets:
        try:
            for account in acct_list:
                if account['Status'] not in ["SUSPENDED", "PENDING_CLOSURE"]:
                    paginator = ic_admin.get_paginator(
                        'list_account_assignments')
                    account_assignment = []
                    for page in paginator.paginate(
                        InstanceArn=ic_instance_arn,
                        AccountId=str(account['Id']),
                        PermissionSetArn=current_aws_permission_sets[each_perm_set_name]['Arn']
                    ):
                        account_assignment.extend(page['AccountAssignments'])
                        logger.debug("Account %s assigment: %s",
                                     account['Id'], page['AccountAssignments'])
                    # Eliminate the empty assignments
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


def process_drift_cleanup(delta_assignment):
    try:
        logger.warning(f"Assignment with drift: {delta_assignment}")
        delete_response = execute_with_retry(
            ic_admin.delete_account_assignment,
            InstanceArn=ic_instance_arn,
            TargetId=delta_assignment['AccountId'],
            TargetType='AWS_ACCOUNT',
            PermissionSetArn=delta_assignment['PermissionSetArn'],
            PrincipalType='GROUP',
            PrincipalId=delta_assignment['PrincipalId']
        )

        if 'AccountAssignmentDeletionStatus' in delete_response:
            request_id = delete_response['AccountAssignmentDeletionStatus']['RequestId']
            complete = False
            while not complete:
                status_response = ic_admin.describe_account_assignment_deletion_status(
                    InstanceArn=ic_instance_arn,
                    AccountAssignmentDeletionRequestId=request_id
                )
                current_status = status_response['AccountAssignmentDeletionStatus']['Status']
                if current_status == 'IN_PROGRESS':
                    sleep(0.5)
                else:
                    complete = True
                    if current_status != 'SUCCEEDED':
                        failure_reason = status_response['AccountAssignmentDeletionStatus'].get(
                            'FailureReason', 'Unknown')
                        log_and_append_error(
                            f"Delete Assignment failed: {failure_reason}")

    except Exception as error:
        log_and_append_error(f"Drift cleanup failed: {str(error)}")


def drift_detect_update(all_assignments, global_file_contents, target_file_contents, current_aws_permission_sets):
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

                target_field = target_mapping.get(
                    'Target', target_mapping.get('TargetAccountid'))
                if not target_field:
                    log_and_append_error(
                        "No Target or TargetAccountid field found in mapping")
                    continue

                if isinstance(target_field, list):
                    resolved_accounts = parse_target_field(
                        target_field, "Target/TargetAccountid")
                else:
                    # Handle direct account IDs for backward compatibility
                    resolved_accounts = parse_target_field(
                        [target_field], "Target/TargetAccountid")
                target_accounts = resolved_accounts

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
        logger.info('Starting parallel drift cleanup')
        with ThreadPoolExecutor(max_workers=ASSIGNMENT_WORKERS) as executor:
            futures = [executor.submit(process_drift_cleanup, delta)
                       for delta in check_list]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Drift cleanup failed: {str(e)}")


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


def process_global_assignment(account, mapping, current_aws_permission_sets):
    """Create global group mapping assignments"""
    try:
        if account['Status'] in ["SUSPENDED", "PENDING_CLOSURE"]:
            return

        for each_perm_set_name in mapping['PermissionSetName']:
            permission_set_arn = get_permission_set_arn(
                each_perm_set_name, current_aws_permission_sets)
            group_id = get_valid_group_id(mapping['GlobalGroupName'])

            if not permission_set_arn or not group_id:
                continue

            logger.debug(
                f"Processing global mapping: {each_perm_set_name} for account: {account}")
            assignment_response = execute_with_retry(
                ic_admin.create_account_assignment,
                InstanceArn=ic_instance_arn,
                TargetId=str(account['Id']),
                TargetType='AWS_ACCOUNT',
                PrincipalType='GROUP',
                PermissionSetArn=permission_set_arn,
                PrincipalId=group_id
            )

            if 'AccountAssignmentCreationStatus' in assignment_response:
                request_id = assignment_response['AccountAssignmentCreationStatus']['RequestId']
                complete = False
                while not complete:
                    status_response = ic_admin.describe_account_assignment_creation_status(
                        InstanceArn=ic_instance_arn,
                        AccountAssignmentCreationRequestId=request_id
                    )
                    current_status = status_response['AccountAssignmentCreationStatus']['Status']
                    if current_status == 'IN_PROGRESS':
                        sleep(0.5)
                    else:
                        complete = True
                        if current_status != 'SUCCEEDED':
                            failure_reason = status_response['AccountAssignmentCreationStatus'].get(
                                'FailureReason', 'Unknown')
                            log_and_append_error(
                                f"Assignment failed for {account['Id']}: {failure_reason}")

    except Exception as error:
        log_and_append_error(
            f"Failed processing {account['Id']}: {str(error)}")


def global_group_array_mapping(acct_list, global_file_contents, current_aws_permission_sets):
    logger.info('Starting parallel global mapping assignments')
    with ThreadPoolExecutor(max_workers=ASSIGNMENT_WORKERS) as executor:
        futures = []
        for mapping in global_file_contents:
            if str(mapping.get('Target', '')).upper() != "GLOBAL":
                continue

            for account in acct_list:
                futures.append(executor.submit(
                    process_global_assignment,
                    account,
                    mapping,
                    current_aws_permission_sets
                ))

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Assignment failed: {str(e)}")


def process_target_assignment(target_account_id, mapping, current_aws_permission_sets):
    try:
        for each_perm_set_name in mapping['PermissionSetName']:
            permission_set_arn = get_permission_set_arn(
                each_perm_set_name, current_aws_permission_sets)
            group_id = get_valid_group_id(mapping['TargetGroupName'])

            if not permission_set_arn or not group_id:
                continue

            logger.info(
                f"Processing target mapping: {each_perm_set_name} for account: {target_account_id}")
            assignment_response = execute_with_retry(
                ic_admin.create_account_assignment,
                InstanceArn=ic_instance_arn,
                TargetId=target_account_id,
                TargetType='AWS_ACCOUNT',
                PrincipalType='GROUP',
                PermissionSetArn=permission_set_arn,
                PrincipalId=group_id
            )

            if 'AccountAssignmentCreationStatus' in assignment_response:
                request_id = assignment_response['AccountAssignmentCreationStatus']['RequestId']
                complete = False
                while not complete:
                    status_response = ic_admin.describe_account_assignment_creation_status(
                        InstanceArn=ic_instance_arn,
                        AccountAssignmentCreationRequestId=request_id
                    )
                    current_status = status_response['AccountAssignmentCreationStatus']['Status']
                    if current_status == 'IN_PROGRESS':
                        sleep(1)
                    else:
                        complete = True
                        if current_status != 'SUCCEEDED':
                            failure_reason = status_response['AccountAssignmentCreationStatus'].get(
                                'FailureReason', 'Unknown')
                            log_and_append_error(
                                f"Assignment failed for {target_account_id}: {failure_reason}")

    except Exception as error:
        log_and_append_error(
            f"Failed processing {target_account_id}: {str(error)}")


def target_group_array_mapping(acct_list, target_file_contents, current_aws_permission_sets):
    logger.info('Starting parallel target mapping assignments')
    with ThreadPoolExecutor(max_workers=ASSIGNMENT_WORKERS) as executor:
        futures = []
        for mapping in target_file_contents:
            target_field = mapping.get(
                'Target', mapping.get('TargetAccountid'))
            resolved_accounts = parse_target_field(
                target_field if isinstance(target_field, list) else [
                    target_field],
                "Target/TargetAccountid"
            )

            for target_account_id in resolved_accounts:
                futures.append(executor.submit(
                    process_target_assignment,
                    target_account_id,
                    mapping,
                    current_aws_permission_sets
                ))

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Assignment failed: {str(e)}")


def get_all_permission_sets(delegated_admin=False):
    """List all the permission sets, with delegated admin check"""
    cache_key = f"permsets_{delegated_admin}"
    cached = cache.get(cache_key)
    if cached:
        return cached
    permission_set_name_and_arn = {}
    try:
        paginator = ic_admin.get_paginator('list_permission_sets')
        all_perm_sets_arns = []
        for page in paginator.paginate(InstanceArn=ic_instance_arn):
            all_perm_sets_arns.extend(page['PermissionSets'])

        global skipped_perm_set
        skipped_perm_set.clear()

        for perm_set_arn in all_perm_sets_arns:
            describe_response = ic_admin.describe_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn
            )
            perm_set = describe_response['PermissionSet']

            if delegated_admin:
                accounts_response = ic_admin.list_accounts_for_provisioned_permission_set(
                    InstanceArn=ic_instance_arn,
                    PermissionSetArn=perm_set_arn
                )
                if management_account_id in accounts_response['AccountIds']:
                    skipped_perm_set[perm_set_arn] = perm_set['Name']
                    continue

            tags_response = ic_admin.list_tags_for_resource(
                InstanceArn=ic_instance_arn,
                ResourceArn=perm_set_arn
            )
            if any(tag['Key'] == 'managedBy' and tag['Value'] == 'ControlTower' for tag in tags_response['Tags']):
                skipped_perm_set[perm_set_arn] = perm_set['Name']
                continue

            permission_set_name_and_arn[perm_set['Name']] = {
                'Arn': perm_set_arn,
                'Description': perm_set.get('Description', '')
            }

        cache.set(cache_key, permission_set_name_and_arn)

    except ClientError as error:
        log_and_append_error(f"List permission sets failed: {error}")
    except Exception as error:
        log_and_append_error(f'Error occurred: {error}')

    return permission_set_name_and_arn

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

def get_org_accounts(delegated_admin=False):
    """Unified account list fetcher"""
    cache_key = f"accounts_{delegated_admin}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    try:
        paginator = orgs_client.get_paginator('list_accounts')
        accounts = []
        for page in paginator.paginate():
            accounts.extend(page['Accounts'])

        filtered_accounts = []

        if delegated_admin:
            filtered_accounts = [acct for acct in accounts
                                 if acct['Id'] != management_account_id
                                 and acct['Status'] not in ["SUSPENDED", "PENDING_CLOSURE"]]
        else:

            filtered_accounts = [acct for acct in accounts
                                 if acct['Status'] not in ["SUSPENDED", "PENDING_CLOSURE"]]
        cache.set(cache_key, filtered_accounts)
        return filtered_accounts

    except ClientError as error:
        log_and_append_error(f"Error listing accounts: {error}")
        return []
    except Exception as error:
        log_and_append_error(f'Error occurred: {error}')
        return []


# @profile(stdout=False, filename='profile_assignment.prof')
def main(event=None):
    """
    Main function to handle Pipeline triggered and EventBridge triggered events for assignment automation.
    """
    logger.debug(f"Delegated: {delegated}")
    delegated_admin = delegated == 'true'
    global errors
    errors = []

    event_create_account_id = None
    event_joined_account_id = None
    event_moved_account_id = None
    event_account_id = None
    event_source = None
    event_id = None
    event_name = None
    user_identity = None
    event_create_ou_id = None
    event_create_ou_name = None
    party1_id = None
    party1_type = None
    party2_id = None
    party2_type = None

    try:
        if build_initiator.startswith('rule'):
            event_source = os.getenv("EVENT_SOURCE")
            # SSO manual changes Event
            if event_source == 'aws.sso' or event_source == 'aws.sso-directory':
                event_id = os.getenv("EVENT_ID")
                event_name = os.getenv("EVENT_NAME")
                user_identity = os.getenv("USER_IDENTITY")
                logger.info(f'This build is triggered by EventBridge with the following parameters:\
                            Event Type: {event}\
                                Event Name: {event_name}\
                                    CloudTrail Event ID: {event_id}\
                                        Event Source: {event_source}\
                                            Performed by user: {user_identity}')
                # SSO Directory changes Event
                if event_source == 'aws.sso-directory':
                    logger.warning(f'This event is generated from source {event_source} and cannot be automatically reverted.\
                                This build will still run to baseline Permission Sets and assignments.\
                                However, please confirm that the initiator event {event_name} is legitimate. If not, revert it manually')
            elif event == 'Scheduled Event':
                logger.info(f'This build is triggered by EventBridge Scheduler running every 12 hours with the following parameters\
                            Event Type: {event}\
                                Event Source: {event_source}')
            # New account created Event
            elif event_source == 'aws.organizations':
                if event == 'AWS Service Event via CloudTrail':
                    event_id = os.getenv("EVENT_ID")
                    event_name = os.getenv("EVENT_NAME")
                    event_create_account_id = os.getenv(
                        "EVENT_CREATE_ACCOUNT_ID")
                    logger.info(f'This build is triggered by EventBridge with the following parameters:\
                                Event Type: {event}\
                                    Event Name: {event_name}\
                                        CloudTrail Event ID: {event_id}\
                                            Event Source: {event_source}\
                                                New AWS account ID: {event_create_account_id}')
                # Account joined/created/moved Organizations Event
                elif event == 'AWS API Call via CloudTrail':
                    event_id = os.getenv("EVENT_ID")
                    event_name = os.getenv("EVENT_NAME")
                    event_create_account_id = os.getenv(
                        "EVENT_CREATE_ACCOUNT_ID")
                    party1_id = os.environ.get('PARTY1_ID')
                    party1_type = os.environ.get('PARTY1_TYPE')
                    party2_id = os.environ.get('PARTY2_ID')
                    party2_type = os.environ.get('PARTY2_TYPE')
                    if party1_type and party1_id and party2_type and party2_id:
                        if party1_type == 'ACCOUNT':
                            event_joined_account_id = party1_id
                        elif party2_type == 'ACCOUNT':
                            event_joined_account_id = party2_id
                    event_moved_account_id = os.getenv(
                        "EVENT_MOVED_ACCOUNT_ID")
                    event_create_ou_id = os.getenv("EVENT_CREATE_OU_ID")
                    event_create_ou_name = os.getenv("EVENT_CREATE_OU_NAME")
                    if event_create_account_id:
                        event_account_id = event_create_account_id
                    elif event_joined_account_id:
                        event_account_id = event_joined_account_id
                    elif event_moved_account_id:
                        event_account_id = event_moved_account_id

                    if event_account_id:
                        logger.info(f'This build is triggered by EventBridge with the following parameters:\
                                Event Type: {event}\
                                    Event Name: {event_name}\
                                        CloudTrail Event ID: {event_id}\
                                            Event Source: {event_source}\
                                                AWS account ID: {event_account_id}')
                    # OU created Event
                    elif event_create_ou_name:
                        logger.info(f'This build is triggered by EventBridge with the following parameters:\
                                Event Type: {event}\
                                    Event Name: {event_name}\
                                        CloudTrail Event ID: {event_id}\
                                            Event Source: {event_source}\
                                                New OU Name: {event_create_ou_name}\
                                                    New OU Id: {event_create_ou_id}')
        elif build_initiator.startswith('codepipeline'):
            logger.info(f'This build is triggered by Pipeline with the following parameters:\
                        Pipeline Name: {build_initiator}\
                            Pipeline Execution ID: {pipeline_execution_id}\
                                Commit ID: {commit_id}.')
        else:
            logger.info(
                f"This build is triggered by {build_initiator} either manually or by an unknown source")

        logger.info("Starting the Process...")

        # Pre-cache critical data
        start_time = time.time()
        logger.info(
            "Starting pre-caching...")

        # Parallel pre-caching
        with ThreadPoolExecutor(max_workers=GENERAL_WORKERS) as executor:
            futures = [
                executor.submit(get_org_accounts, delegated_admin),
                executor.submit(get_all_permission_sets, delegated_admin)
            ]

            for future in as_completed(futures):
                future.result()  # trigger caching

        logger.info(
            f"Pre-caching completed in {time.time() - start_time:.2f}s")

        # Get accounts and permission sets
        acct_list = get_org_accounts(delegated_admin)
        current_aws_permission_sets = get_all_permission_sets(delegated_admin)
        if not current_aws_permission_sets:
            error_message = "Cannot load existing Permission Sets from AWS IAM Identity Center!"
            log_and_append_error(error_message)
            if errors:
                error_message = f'Errors encountered during processing: {errors}'
            sys.exit(1)
        else:
            logger.info("The current permision sets in this account:%s",
                        json.dumps(current_aws_permission_sets, indent=2))
        # Load mapping files
        global_file_contents = get_global_mapping_contents(
            ic_bucket_name, global_mapping_file_name)
        target_file_contents = get_target_mapping_contents(
            ic_bucket_name, target_mapping_file_name)

        # Process assignments
        with ThreadPoolExecutor(max_workers=GENERAL_WORKERS) as general_executor:
            global_future = general_executor.submit(
                global_group_array_mapping, acct_list, global_file_contents, current_aws_permission_sets)
            target_future = general_executor.submit(
                target_group_array_mapping, acct_list, target_file_contents, current_aws_permission_sets)
            for future in as_completed([global_future, target_future]):
                future.result()

        # Drift detection and cleanup
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
            logger.debug(f"Cache effectiveness:")
            logger.info(f"Total cached entries: {len(cache._cache)}")

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
