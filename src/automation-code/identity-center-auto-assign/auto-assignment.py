"""Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved"""
# pylint: disable=C0301
# pylint: disable=W1202,W0703
# pylint: disable=E0401
from functools import lru_cache
import os
import json
import logging
import re
import sys
from time import sleep
import time
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config
import watchtower
from typing import List, Dict, Union, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
from threading import Lock
# from functools import lru_cache
# from profilehooks import profile

ASSIGNMENT_WORKERS = 10  # For Create/DeleteAccountAssignment
GENERAL_WORKERS = 20     # For read/list operations
RETRY_BASE_DELAY = 1     # Base delay for exponential backoff in seconds
CACHE_TTL = 1800  # 30 minutes
progress_lock = Lock()

AWS_CONFIG = Config(
    retries=dict(
        max_attempts=5,
        mode='adaptive'
    ),
    max_pool_connections=10+ASSIGNMENT_WORKERS + GENERAL_WORKERS
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

# Cache storage
class CacheManager:
    def __init__(self):
        self._cache = {}
        self._timestamps = {}
        self._hits = 0
        self._misses = 0
        self._sets = 0

    def get(self, key):
        current_time = time.time()
        if key in self._cache:
            if current_time - self._timestamps.get(key, 0) < CACHE_TTL:
                self._hits += 1
                logger.debug(f"Cache HIT for key: {key}")
                return self._cache[key]
            else:
                # Cache entry expired
                self._misses += 1
                logger.debug(f"Cache MISS (expired) for key: {key}")
                del self._cache[key]
                del self._timestamps[key]
                return None
        self._misses += 1
        logger.debug(f"Cache MISS (not found) for key: {key}")
        return None

    def set(self, key, value):
        self._cache[key] = value
        self._timestamps[key] = time.time()
        self._sets += 1
        logger.debug(f"Cache SET for key: {key}")

    def delete(self, key):
        """Delete a key from the cache"""
        if key in self._cache:
            del self._cache[key]
            del self._timestamps[key]
            self._deletes += 1
            logger.debug(f"Cache DELETE for key: {key}")
            return True
        return False

    def get_stats(self):
        """Return cache statistics"""
        total_requests = self._hits + self._misses
        hit_rate = (self._hits / total_requests *
                    100) if total_requests > 0 else 0
        return {
            'hits': self._hits,
            'misses': self._misses,
            'sets': self._sets,
            'hit_rate': f"{hit_rate:.2f}%",
            'current_size': len(self._cache),
            'keys': list(self._cache.keys())
        }

    def print_stats(self):
        """Print cache statistics"""
        stats = self.get_stats()
        logger.info("Cache Statistics:")
        logger.info(f"Hits: {stats['hits']}")
        logger.info(f"Misses: {stats['misses']}")
        logger.info(f"Sets: {stats['sets']}")
        logger.info(f"Hit Rate: {stats['hit_rate']}")
        logger.info(f"Current Size: {stats['current_size']}")
        logger.info(f"Cached Keys: {stats['keys']}")


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
            sleep_time = RETRY_BASE_DELAY * \
                (2 ** attempt) + random.uniform(0, 1)
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
    cache_key = f"target_field_{hash(str(target_data))}"
    if cached := cache.get(cache_key):
        return cached

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
                    if ou_accounts := cache.get(f"ou_{ou_path}"):
                        resolved_accounts.update(ou_accounts)
                    else:
                        accounts = get_accounts_in_ou(ou_path)
                        cache.set(f"ou_{ou_path}", accounts)
                        resolved_accounts.update(accounts)

            # Process account names/IDs
            if 'Accounts' in target:
                for account in target['Accounts']:
                    # Verify account is an ID (12 digit number)
                    if re.match(r'^\d{12}$', account):
                        resolved_accounts.add(account)
                    else:
                        if account_id := cache.get(f"account_name_{account}"):
                            resolved_accounts.add(account_id)
                        else:
                            account_id = get_account_id_by_name(account)
                            if account_id:
                                cache.set(
                                    f"account_name_{account}", account_id)
                                resolved_accounts.add(account_id)

    result = list(resolved_accounts)
    cache.set(cache_key, result)
    logger.debug(f'Cached parsed target field result')
    return result


def get_all_permission_sets(delegated_admin=False):
    """Get filtered permission sets with parallel processing"""
    cache_key = f"permsets_{delegated_admin}"
    if cached := cache.get(cache_key):
        return cached

    permission_sets = {}
    skipped = set()

    try:
        # List all permission set ARNs
        paginator = ic_admin.get_paginator('list_permission_sets')
        all_arns = []
        for page in paginator.paginate(InstanceArn=ic_instance_arn):
            all_arns.extend(page['PermissionSets'])

        def process_perm_set(arn):
            try:
                desc_response = execute_with_retry(
                    ic_admin.describe_permission_set,
                    InstanceArn=ic_instance_arn,
                    PermissionSetArn=arn
                )
                ps = desc_response['PermissionSet']
                name = ps['Name']

                tags = execute_with_retry(
                    ic_admin.list_tags_for_resource,
                    InstanceArn=ic_instance_arn,
                    ResourceArn=arn
                )['Tags']
                if any(t['Key'] == 'managedBy' and t['Value'] == 'ControlTower' for t in tags):
                    skipped.add((name, arn, "Control Tower"))
                    return None

                if delegated_admin:
                    account_ids = []
                    paginator = ic_admin.get_paginator(
                        'list_accounts_for_provisioned_permission_set')
                    for page in paginator.paginate(
                        InstanceArn=ic_instance_arn,
                        PermissionSetArn=arn
                    ):
                        account_ids.extend(page['AccountIds'])
                    if management_account_id in account_ids:
                        skipped.add((name, arn, "management account"))
                        return None

                return {name: {'Arn': arn}}

            except Exception as e:
                logger.error(f"Error processing {arn}: {str(e)}")
                return None

        with ThreadPoolExecutor(max_workers=GENERAL_WORKERS) as executor:
            futures = [executor.submit(process_perm_set, arn)
                       for arn in all_arns]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    permission_sets.update(result)

        # Log skipped permission sets
        for name, arn, reason in skipped:
            log_skipped_once(name, arn, reason)

        cache.set(cache_key, permission_sets)
        return permission_sets

    except Exception as error:
        logger.error(f"Permission set processing failed: {str(error)}")
        raise


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


def list_all_current_account_assignment(active_accounts, current_aws_permission_sets):
    """Parallelized current assignments listing"""
    all_assignments = []
    logger.info(
        "Getting all current account assignments from Identity Center. Please wait...")

    def process_assignment(account, perm_set_arn):
        try:
            assignments = []
            for page in ic_admin.get_paginator('list_account_assignments').paginate(
                InstanceArn=ic_instance_arn,
                AccountId=account['Id'],
                PermissionSetArn=perm_set_arn
            ):
                assignments.extend(page['AccountAssignments'])
            return [a for a in assignments if a['PrincipalType'] == 'GROUP']
        except Exception as error:
            logger.error(f"Error processing {account['Id']}: {error}")
            return []

    with ThreadPoolExecutor(max_workers=GENERAL_WORKERS) as executor:
        futures = []
        for perm_set in current_aws_permission_sets.values():
            for account in active_accounts:
                futures.append(executor.submit(
                    process_assignment, account, perm_set['Arn']
                ))

        for future in as_completed(futures):
            all_assignments.extend(future.result())

    return all_assignments


def generate_expected_assignments(global_mappings, target_mappings, current_aws_permission_sets, active_accounts):
    """Generate expected assignments using set operations"""
    expected = set()

    active_account_ids = {account['Id'] for account in active_accounts}

    # Process global mappings
    for mapping in global_mappings:
        if str(mapping.get('Target', '')).upper() != "GLOBAL":
            continue
        group_id = get_valid_group_id(mapping['GlobalGroupName'])
        if not group_id:
            continue
        for perm_set_name in mapping['PermissionSetName']:
            perm_set_arn = current_aws_permission_sets.get(
                perm_set_name, {}).get('Arn')
            if perm_set_arn:
                for account_id in active_accounts:
                    expected.add((account_id, perm_set_arn, group_id))

    # Process target mappings
    for mapping in target_mappings:
        group_id = get_valid_group_id(mapping['TargetGroupName'])
        if not group_id:
            continue
        for perm_set_name in mapping['PermissionSetName']:
            perm_set_arn = current_aws_permission_sets.get(
                perm_set_name, {}).get('Arn')
            if perm_set_arn:
                target_field = mapping.get(
                    'Target', mapping.get('TargetAccountid'))
                resolved_accounts = parse_target_field(
                    target_field if isinstance(target_field, list) else [
                        target_field]
                )
                valid_accounts = set(resolved_accounts) & active_account_ids
                for account_id in valid_accounts:
                    expected.add((account_id, perm_set_arn, group_id))

    return expected


def create_required_assignments(expected_assignments, current_assignments, current_aws_permission_sets):
    """Create missing assignments using parallel processing"""
    current_set = {(a['AccountId'], a['PermissionSetArn'], a['PrincipalId'])
                   for a in current_assignments}
    required_assignments = expected_assignments - current_set
    if not required_assignments:
        logger.info("No new assignments to create. ")
        return

    total = len(required_assignments)
    logger.info(f"Creating {total} new assignments")

    completed = 0
    progress_lock = Lock()

    def update_progress():
        nonlocal completed
        with progress_lock:
            completed += 1
            if completed == 1:
                logger.info(
                    f"Progress: Created {completed}/{total} assignments")
            elif completed % 10 == 0 or completed == total:
                logger.info(
                    f"Progress: Created {completed}/{total} assignments")

    with ThreadPoolExecutor(max_workers=ASSIGNMENT_WORKERS) as executor:
        futures = []
        for account_id, perm_set_arn, group_id in required_assignments:
            perm_set_name = get_perm_set_name_from_arn(
                perm_set_arn, current_aws_permission_sets)
            futures.append(executor.submit(
                process_assignment_creation,
                account_id,
                perm_set_arn,
                group_id,
                perm_set_name,
                update_progress
            ))

        for future in as_completed(futures):
            try:
                result = future.result()
                if result and 'AccountAssignmentCreationStatus' in result:
                    track_creation_status(
                        result['AccountAssignmentCreationStatus']['RequestId'])
            except Exception as e:
                logger.error(f"Assignment creation failed: {str(e)}")


def process_assignment_creation(target_account_id, perm_set_arn, group_id, perm_set_name, progress_counter):
    """Create a single assignment with retry logic"""
    try:
        logger.info(
            f"Creating assignment: {perm_set_name} => {target_account_id}")
        response = execute_with_retry(
            ic_admin.create_account_assignment,
            InstanceArn=ic_instance_arn,
            TargetId=target_account_id,
            TargetType='AWS_ACCOUNT',
            PrincipalType='GROUP',
            PermissionSetArn=perm_set_arn,
            PrincipalId=group_id
        )
        if progress_counter:
            progress_counter()
        return response
    except Exception as error:
        logger.error(f"Assignment creation failed: {str(error)}")
        return None


def track_creation_status(request_id):
    """Track status of assignment creation requests"""
    while True:
        status = ic_admin.describe_account_assignment_creation_status(
            InstanceArn=ic_instance_arn,
            AccountAssignmentCreationRequestId=request_id
        )['AccountAssignmentCreationStatus']

        if status['Status'] != 'IN_PROGRESS':
            if status['Status'] != 'SUCCEEDED':
                logger.error(
                    f"Creation failed: {status.get('FailureReason', 'Unknown')}")
            break
        sleep(0.5)

def drift_detect_update(all_assignments, expected_assignments, current_aws_permission_sets):
    """Efficient drift detection using set operations"""
    current_set = {
        (a['AccountId'], a['PermissionSetArn'], a['PrincipalId'])
        for a in all_assignments
    }
    drift_set = current_set - expected_assignments

    if not drift_set:
        logger.info(
            "No drifted assignments found in Identity Center. Skipping drift detection.")
        return

    total_drifts = len(drift_set)
    logger.info(f"Found {total_drifts} drifted assignments")

    completed = 0
    progress_lock = Lock()

    def update_progress():
        nonlocal completed
        with progress_lock:
            completed += 1
            if completed == 1:
                logger.info(
                    f"Progress: Deleted {completed}/{total_drifts} assignments")
            elif completed % 10 == 0 or completed == total_drifts:
                logger.info(
                    f"Progress: Deleted {completed}/{total_drifts} assignments")

    with ThreadPoolExecutor(max_workers=ASSIGNMENT_WORKERS) as executor:
        futures = []
        for account_id, perm_set_arn, principal_id in drift_set:
            perm_set_name = get_perm_set_name_from_arn(
                perm_set_arn, current_aws_permission_sets)
            logger.info(
                f"Deleting assignment: {perm_set_name} => {account_id}")
            futures.append(executor.submit(
                process_drift_cleanup,
                {'AccountId': account_id, 'PermissionSetArn': perm_set_arn,
                    'PrincipalId': principal_id},
                perm_set_name,
                update_progress
            ))

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Drift cleanup failed: {str(e)}")


def process_drift_cleanup(delta_assignment, perm_set_name, progress_counter):
    """Handle single drift cleanup"""
    logger.info(
        f"Deleting assignment: {perm_set_name} => {delta_assignment['AccountId']}")
    try:
        delete_response = execute_with_retry(
            ic_admin.delete_account_assignment,
            InstanceArn=ic_instance_arn,
            TargetId=delta_assignment['AccountId'],
            TargetType='AWS_ACCOUNT',
            PermissionSetArn=delta_assignment['PermissionSetArn'],
            PrincipalType='GROUP',
            PrincipalId=delta_assignment['PrincipalId']
        )
        request_id = delete_response['AccountAssignmentDeletionStatus']['RequestId']
        while True:
            status = ic_admin.describe_account_assignment_deletion_status(
                InstanceArn=ic_instance_arn,
                AccountAssignmentDeletionRequestId=request_id
            )['AccountAssignmentDeletionStatus']
            if status['Status'] != 'IN_PROGRESS':
                if status['Status'] != 'SUCCEEDED':
                    logger.error(
                        f"Deletion failed: {status.get('FailureReason', 'Unknown')}")
                break
        if progress_counter:
            progress_counter()
            sleep(0.5)
    except Exception as error:
        logger.error(f"Drift cleanup failed: {str(error)}")


def get_global_mapping_contents(bucketname, global_mapping_file):
    """Get global mapping info from JSON files"""
    try:
        logger.info("Getting global mapping info from JSON files")
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


def log_skipped_once(name, arn, reason):
    """Warn once per permission set"""
    global skipped_perm_set
    if name not in skipped_perm_set:
        logger.warning(f"Skipping {name} ({reason} managed)")
        skipped_perm_set.update({arn: name})


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


def get_perm_set_name_from_arn(perm_set_arn, current_aws_permission_sets):
    """Get the IAM Identity Center permission set names from arns"""
    for name, info in current_aws_permission_sets.items():
        if info['Arn'] == perm_set_arn:
            return name
    return "Unknown"


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
                                 if acct['Id'] != management_account_id and acct['Status'] == "ACTIVE"]
        else:

            filtered_accounts = [acct for acct in accounts
                                 if acct['Status'] == "ACTIVE"]
        cache.set(cache_key, filtered_accounts)
        return filtered_accounts

    except ClientError as error:
        log_and_append_error(f"Error listing accounts: {error}")
        return []
    except Exception as error:
        log_and_append_error(f'Error occurred: {error}')
        return []


# @profile(stdout=False, filename='profile_assignment_new.prof')
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
        logger.info("Pre-caching critical data...")

        # Get accounts and permission sets
        with ThreadPoolExecutor(max_workers=GENERAL_WORKERS) as executor:
            accounts_future = executor.submit(
                get_org_accounts, delegated_admin)
            permission_sets_future = executor.submit(
                get_all_permission_sets, delegated_admin)
            accounts = accounts_future.result()
            current_aws_permission_sets = permission_sets_future.result()

        elapsed = time.time() - start_time
        logger.info(
            f"Pre-caching completed in {f'{elapsed / 60:.2f} minutes' if elapsed > 60 else f'{elapsed:.2f} seconds'}")

        logger.info(
            f"Found {len(current_aws_permission_sets)} current permission sets in Identity Center")
        logger.debug("""The current permision sets in Identity Center:
                    %s""", json.dumps(current_aws_permission_sets, indent=2))

        # Load mapping files
        with ThreadPoolExecutor(max_workers=GENERAL_WORKERS) as executor:
            global_future = executor.submit(
                get_global_mapping_contents, ic_bucket_name, global_mapping_file_name)
            target_future = executor.submit(
                get_target_mapping_contents, ic_bucket_name, target_mapping_file_name)
            global_mappings = global_future.result()
            target_mappings = target_future.result()

        # Generate expected assignments
        expected_assignments = generate_expected_assignments(
            global_mappings, target_mappings, current_aws_permission_sets, accounts
        )

        start_time = time.time()
        # Get current assignments
        current_assignments = list_all_current_account_assignment(
            accounts, current_aws_permission_sets)

        elapsed = time.time() - start_time
        logger.info(
            f"Scanning Identity Center assignments completed in {f'{elapsed / 60:.2f} minutes' if elapsed > 60 else f'{elapsed:.2f} seconds'}")

        logger.info(
            f"Found {len(current_assignments)} current assignments in Identity Center")

        # Create missing assignments
        create_required_assignments(
            expected_assignments, current_assignments, current_aws_permission_sets)

        # Clean up drifted assignments
        drift_detect_update(current_assignments,
                            expected_assignments, current_aws_permission_sets)
        # cache.print_stats()

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
