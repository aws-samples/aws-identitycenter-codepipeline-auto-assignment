"""Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved"""
# pylint: disable=C0301
# pylint: disable=W1202,W0703
# pylint: disable=E0401
from time import sleep
import json
import os
import logging
import sys
import watchtower
from botocore.config import Config
import boto3
from botocore.exceptions import ClientError
# from profilehooks import profile
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
from functools import lru_cache
import time
from threading import Lock

GENERAL_WORKERS = 20     # For read/list operations
RETRY_BASE_DELAY = 1     # Base delay for exponential backoff

AWS_CONFIG = Config(
    retries=dict(
        max_attempts=5,
        mode='adaptive'
    ),
    max_pool_connections=20+GENERAL_WORKERS
)

# Global provisioning task store with thread-safe lock
provisioning_tasks = []
provisioning_lock = Lock()

runtime_region = os.getenv('AWS_REGION')
ic_bucket_name = os.getenv('IC_S3_BucketName')
s3 = boto3.resource('s3')
orgs_client = boto3.client('organizations', region_name=runtime_region)
sns_client = boto3.client('sns', region_name=runtime_region)
ic_admin = boto3.client(
    'sso-admin', region_name=runtime_region, config=AWS_CONFIG)
ic_instance_arn = os.getenv('IC_InstanceArn')
default_session_duration = 'PT1H'
management_account_id = os.getenv('Org_Management_Account')
delegated = os.getenv('AdminDelegated')
dynamodb = boto3.client('dynamodb', region_name=runtime_region)
logs_client = boto3.client('logs', region_name=runtime_region)
permission_set_automation_log_group = os.getenv(
    'PermissionSetAutomationLogGroupName')
codebuild_build_id = os.getenv('CODEBUILD_BUILD_ID')
build_name, build_id = codebuild_build_id.split(':')
event_env = os.getenv("EVENT_DATA")
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
    log_group=permission_set_automation_log_group,
    stream_name=f"[buildId]-{build_id}",
    boto3_client=logs_client
)
watchtower_handler.setLevel(logging.INFO)

formatter_no_timestamp = logging.Formatter('%(levelname)s - %(message)s')
watchtower_handler.setFormatter(formatter_no_timestamp)
logger.addHandler(watchtower_handler)

# Add boto3 logger to log API retry events
boto_logger = logging.getLogger('botocore')
boto_logger.setLevel(logging.DEBUG)

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


def is_retryable_error(error):
    if isinstance(error, ClientError):
        code = error.response['Error']['Code']
        return code in ['ThrottlingException', 'RequestLimitExceeded']
    return False


def execute_with_retry(func, *args, **kwargs):
    """Enhanced retry helper with exponential backoff"""
    max_attempts = kwargs.pop('max_attempts', 5)
    for attempt in range(max_attempts):
        try:
            return func(*args, **kwargs)
        except (ClientError, ic_admin.exceptions.ConflictException) as error:
            if attempt == max_attempts - 1 or not is_retryable_error(error):
                raise
            base_delay = RETRY_BASE_DELAY * (2 ** attempt)
            sleep(base_delay + random.uniform(0, 1))
        except Exception as error:
            logger.error(f"Unexpected error in {func.__name__}: {str(error)}")
            raise


def process_permission_set(local_perm_set, aws_permission_sets):
    """Process a single permission set in parallel"""
    local_errors = []
    perm_set_name = local_perm_set['Name']
    local_description = local_perm_set.get('Description', '')
    local_session_duration = local_perm_set.get(
        'Session_Duration', default_session_duration)

    # Check if this permission set should be skipped
    global skipped_perm_set
    if any(name == perm_set_name for arn, name in skipped_perm_set.items()):
        # skip and continue to next permission set
        return []

    try:
        # Check if permission set exists
        if perm_set_name in aws_permission_sets:
            logger.info(f"Permission set {perm_set_name} exists. Syncing.")
            perm_set_arn = aws_permission_sets[perm_set_name]['Arn']
            aws_session_duration = aws_permission_sets[perm_set_name]['SessionDuration']
            local_tags = local_perm_set.get('Tags', [])
            aws_description = aws_permission_sets[perm_set_name]['Description']
        else:
            # Create new permission set
            logger.info(
                f"Permission Set doesn't exist. Creating new permission set: {perm_set_name}")
            response = execute_with_retry(
                ic_admin.create_permission_set,
                Name=perm_set_name,
                Description=local_description,
                InstanceArn=ic_instance_arn,
                Tags=local_tags,
                SessionDuration=local_session_duration
            )
            perm_set_arn = response['PermissionSet']['PermissionSetArn']
            aws_session_duration = response['PermissionSet']['SessionDuration']
            aws_description = response['PermissionSet']['Description']

        # Sync permission set components
        components = [
            ('ManagedPolicies', sync_managed_policies),
            ('CustomerPolicies', sync_customer_policies),
            ('InlinePolicies', sync_inline_policies),
            ('PermissionsBoundary', sync_permissions_boundary),
            ('Tags', sync_tags)
        ]

        with ThreadPoolExecutor(max_workers=len(components)) as executor:
            futures = []
            for key, func in components:
                if key in local_perm_set:
                    futures.append(executor.submit(
                        execute_with_retry, func, perm_set_name,
                        local_perm_set[key], perm_set_arn
                    ))
            futures.append(executor.submit(
                execute_with_retry, sync_description, perm_set_name, perm_set_arn,
                local_description, aws_description
            ))

            futures.append(executor.submit(
                execute_with_retry, sync_session_duration, perm_set_name,
                perm_set_arn, aws_session_duration, local_session_duration
            ))
            for future in as_completed(futures):
                future.result()

        execute_with_retry(is_required_provisioning,
                           perm_set_name, perm_set_arn)
    except Exception as e:
        local_errors.append(f"{perm_set_name} processing failed: {str(e)}")

    return local_errors


def is_required_provisioning(perm_set_name, perm_set_arn):
    """Parallel check for accounts needing provisioning"""
    logger.info(f"Checking if {perm_set_name} requires provisioning...")
    account_ids = get_provisioned_accounts(perm_set_arn)
    if not account_ids:
        logger.info(f"No accounts found for {perm_set_name}")
        return

    active_accounts = [account for account in account_ids
                       if is_account_active(account)]
    logger.debug(f"Active accounts assigned to {perm_set_name}")

    if not active_accounts:
        logger.info(f"No active accounts found for {perm_set_name}")
        return

    needs_provisioning = False

    with ThreadPoolExecutor(max_workers=GENERAL_WORKERS) as executor:
        futures = [executor.submit(
            is_provisioned_or_outdated,
            perm_set_name,
            perm_set_arn,
            account
        ) for account in active_accounts]

        for future in as_completed(futures):
            try:
                if (result := future.result()):
                    with provisioning_lock:
                        provisioning_tasks.append(result)
                        needs_provisioning = True
            except Exception as error:
                logger.error(f"Provisioning check failed: {error}")
    if not needs_provisioning:
        logger.info(
            f"Permission set {perm_set_name} is up-to-date and requires no provisioning")


def is_provisioned_or_outdated(perm_set_name, perm_set_arn, account):
    """Check if account needs provisioning"""
    try:
        # Check never provisioned
        provisioned = ic_admin.list_permission_sets_provisioned_to_account(
            InstanceArn=ic_instance_arn,
            AccountId=account
        ).get('PermissionSets', [])

        if perm_set_arn not in provisioned:
            return (perm_set_name, perm_set_arn, account, 'never_provisioned')

        # Check outdated
        outdated = ic_admin.list_permission_sets_provisioned_to_account(
            InstanceArn=ic_instance_arn,
            AccountId=account,
            ProvisioningStatus='LATEST_PERMISSION_SET_NOT_PROVISIONED'
        ).get('PermissionSets', [])

        if perm_set_arn in outdated:
            return (perm_set_name, perm_set_arn, account, 'outdated')

    except Exception as error:
        logger.error(f"Status check failed for {account}: {str(error)}")
    logger.debug(f"No provisioning required for {perm_set_name}")
    return None


def provisioning_job():
    """Process all collected provisioning tasks with 3-second intervals"""
    if not provisioning_tasks:
        return

    logger.info(
        f"Executing {len(provisioning_tasks)} provisioning tasks for new or outdated permission sets")
    for idx, task in enumerate(provisioning_tasks, 1):
        perm_set_name, perm_set_arn, account, reason = task
        logger.info(
            f"Processing {idx}/{len(provisioning_tasks)}: {perm_set_name} for {account} ({reason})")

        try:
            provision_account(perm_set_name, perm_set_arn, account)
        except Exception as error:
            logger.error(f"Failed to provision {account}: {str(error)}")

        if idx < len(provisioning_tasks):
            time.sleep(3)


def provision_account(perm_set_name, perm_set_arn, account, max_attempts=7):
    """Provision account with 2-second status checks"""
    attempt = 0
    while attempt < max_attempts:
        try:
            response = ic_admin.provision_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                TargetType='AWS_ACCOUNT',
                TargetId=account
            )
            request_id = response['PermissionSetProvisioningStatus']['RequestId']

            while True:
                status = ic_admin.describe_permission_set_provisioning_status(
                    InstanceArn=ic_instance_arn,
                    ProvisionPermissionSetRequestId=request_id
                )['PermissionSetProvisioningStatus']['Status']

                if status == 'SUCCEEDED':
                    logger.info(
                        f"Successfully provisioned {perm_set_name} to account {account}")
                    return
                if status in ['FAILED', 'CANCELLED']:
                    raise Exception("Provisioning failed")
                sleep(2)

        except Exception as error:
            attempt += 1
            if attempt >= max_attempts:
                raise
            sleep(RETRY_BASE_DELAY * (2 ** attempt))


def is_required_deprovisioning(perm_set_name, perm_set_arn):
    """Parallel check for accounts needing deprovisioning"""

    provisioned_accounts = set()
    deprovisioning_tasks = []

    account_ids = get_provisioned_accounts(perm_set_arn)
    if not account_ids:
        logger.info(f"No accounts found for {perm_set_name}")
        return deprovisioning_tasks

    active_accounts = [account for account in account_ids
                       if is_account_active(account)]

    if not active_accounts:
        logger.info(f"No active accounts found for {perm_set_name}")
        return deprovisioning_tasks

    # Create deprovisioning tasks for each active account
    for account in active_accounts:
        deprovisioning_tasks.append((perm_set_name, perm_set_arn, account))

    logger.info(
        f"Found {len(deprovisioning_tasks)} accounts to deprovision for {perm_set_name}")
    return deprovisioning_tasks


def deprovisioning_job(permission_sets):
    """Process all collected deprovisioning tasks with 3-second intervals"""
    if not permission_sets:
        return
    logger.info(
        f"Checking {len(permission_sets)} permission sets for deprovisioning")

    confirmed_tasks = []
    deprovisioned_sets = set()

    try:
        with ThreadPoolExecutor(max_workers=GENERAL_WORKERS) as executor:
            futures = [
                executor.submit(
                    execute_with_retry,
                    is_required_deprovisioning,
                    name,
                    arn
                ) for name, arn in permission_sets
            ]

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:  # If deprovisioning is required
                        confirmed_tasks.extend(result)
                except Exception as error:
                    logger.error(f"Deprovisioning check failed: {error}")
        if not confirmed_tasks:
            logger.info("No permission sets require deprovisioning")
            return

        logger.info(f"Starting deprovisioning of {len(confirmed_tasks)} tasks")
        # Process in batches of 10
        for i in range(0, len(confirmed_tasks), 10):
            batch = confirmed_tasks[i:i + 10]
            logger.info(
                f"Processing batch {i//10 + 1}: {len(batch)} assignments")

            # 10 parallel jobs to stay under IdC API throttle limits
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [
                    executor.submit(
                        execute_with_retry,
                        deprovision_account,
                        perm_set_arn,
                        perm_set_name,
                        account
                    ) for perm_set_name, perm_set_arn, account in batch
                ]

                # Wait for all tasks in this batch to complete
                for future in as_completed(futures):
                    try:
                        success, name, arn = future.result()
                        if success:
                            deprovisioned_sets.add((name, arn))
                    except Exception as error:
                        logger.error(f"Deprovisioning failed: {error}")

            if i + 10 < len(confirmed_tasks):
                time.sleep(2)

        if deprovisioned_sets:
            logger.info(
                f"Starting deletion of {len(deprovisioned_sets)} permission sets")
            with ThreadPoolExecutor(max_workers=GENERAL_WORKERS) as executor:
                deletion_futures = [
                    executor.submit(
                        execute_with_retry,
                        delete_permission_set,
                        arn,
                        name
                    ) for name, arn in deprovisioned_sets
                ]

                for future in as_completed(deletion_futures):
                    try:
                        name, arn = future.result()
                        logger.info(
                            f"Successfully deleted permission set: {name}")
                    except Exception as error:
                        logger.error(
                            f"Permission set deletion failed: {error}")

    except Exception as error:
        logger.error(f"Error in deprovisioning job: {error}")
        raise


def deprovision_account(perm_set_arn, perm_set_name, account):
    """Deprovision a permission set from a specific account"""
    try:
        assignments = ic_admin.list_account_assignments(
            InstanceArn=ic_instance_arn,
            AccountId=account,
            PermissionSetArn=perm_set_arn
        )['AccountAssignments']

        for assignment in assignments:
            delete_response = ic_admin.delete_account_assignment(
                InstanceArn=ic_instance_arn,
                TargetId=account,
                TargetType='AWS_ACCOUNT',
                PermissionSetArn=perm_set_arn,
                PrincipalType=assignment['PrincipalType'],
                PrincipalId=assignment['PrincipalId']
            )
            request_id = delete_response['AccountAssignmentDeletionStatus']['RequestId']
            while True:
                status = ic_admin.describe_account_assignment_deletion_status(
                    InstanceArn=ic_instance_arn,
                    AccountAssignmentDeletionRequestId=request_id
                )['AccountAssignmentDeletionStatus']['Status']
                if status == 'SUCCEEDED':
                    logger.info(
                        f"Successfully deprovisioned {perm_set_name} from account {account}")
                    break
                if status in ['FAILED', 'CANCELLED']:
                    raise Exception("Deprovisioning failed")
                sleep(2)
        return True, perm_set_name, perm_set_arn

    except ic_admin.exceptions.ResourceNotFoundException:
        logger.info(
            f"Account assignment not found for {perm_set_name} in account {account}"
        )
        return True, perm_set_name, perm_set_arn
    except Exception as error:
        logger.error(
            f"Failed to deprovision {perm_set_name} from {account}: {str(error)}"
        )
        return False, perm_set_name, perm_set_arn


def delete_permission_set(perm_set_arn, perm_set_name):
    """Delete a permission set"""
    try:
        ic_admin.delete_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )
        logger.info(f"Deleted permission set {perm_set_name}")
        cache.set(f"permsets_{delegated}", None)
        return perm_set_name, perm_set_arn
    except ic_admin.exceptions.ResourceNotFoundException:
        logger.warning(f"Permission set {perm_set_name} not found")
        return perm_set_name, perm_set_arn
    except Exception as error:
        raise Exception(
            f"Failed to delete permission set {perm_set_name}: {str(error)}")


def sync_json_with_aws(local_files, aws_permission_sets):
    """Main sync workflow"""
    all_errors = []

    # Process permission sets
    with ThreadPoolExecutor(max_workers=GENERAL_WORKERS) as executor:
        futures = [executor.submit(process_permission_set, f, aws_permission_sets)
                   for f in local_files.values()]
        all_errors.extend(err for future in as_completed(futures)
                          for err in future.result())

    # Delete obsolete permission sets using set operations
    local_names = {ps['Name'] for ps in local_files.values()}
    aws_names = set(aws_permission_sets.keys())
    to_delete = [(name, aws_permission_sets[name]['Arn'])
                 for name in (aws_names - local_names)]

    if to_delete:
        deprovisioning_job(to_delete)
    else:
        logger.info("No permission sets marked for deletion. Skipping...")

    # Execute queued provisioning tasks
    provisioning_job()

    return all_errors


def sync_table_for_skipped_perm_sets(skipped_perm_set):
    """Sync DynamoDB table with the list of skipped permission sets if Admin is delegated"""
    try:
        logger.info(
            "Scanning 'ic-SkippedPermissionSetsTable' DynamoDb table for existing skipped permission sets")
        response = dynamodb.scan(
            TableName='ic-SkippedPermissionSetsTable')
        items = response['Items']
        logger.info(
            f"Found {len(items)} in 'ic-SkippedPermissionSetsTable' DynamoDb table")
        for item in items:
            # If the permission set is not in the current skipped_perm_set, delete it from the table
            if item['perm_set_arn']['S'] not in skipped_perm_set:
                dynamodb.delete_item(
                    TableName='ic-SkippedPermissionSetsTable',
                    Key={'perm_set_arn': item['perm_set_arn']}
                )
                logger.debug(
                    f"Drift detected in DynamoDB table. Deleted item: {item} from table.")

        # Update the table with all permission sets in the skipped_perm_set
        batch = dynamodb.batch_write_item(RequestItems={
            'ic-SkippedPermissionSetsTable': [
                {
                    'PutRequest': {
                        'Item': {
                            'perm_set_arn': {'S': perm_set_arn},
                            'perm_set_name': {'S': perm_set_name}
                        }
                    }
                } for perm_set_arn, perm_set_name in skipped_perm_set.items()
            ]
        })

        # Get all skipped permission sets that were unprocessed
        unprocessed_items = batch.get('UnprocessedItems')
        if unprocessed_items:
            error_message = f"There were unprocessed skipped permission sets while writing to DynamoDB table: {unprocessed_items}"
            log_and_append_error(error_message)
        else:
            logger.info(
                "All skipped permission sets written successfully to the table")

    except ClientError as error:
        error_message = f"Client error occurred: {error}"
        log_and_append_error(error_message)
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)


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

        # Parallel processing of permission sets
        def process_perm_set(arn):
            try:
                # Describe permission set
                desc_response = execute_with_retry(
                    ic_admin.describe_permission_set,
                    InstanceArn=ic_instance_arn,
                    PermissionSetArn=arn
                )
                ps = desc_response['PermissionSet']
                name = ps['Name']

                # Check Control Tower management
                tags = execute_with_retry(
                    ic_admin.list_tags_for_resource,
                    InstanceArn=ic_instance_arn,
                    ResourceArn=arn
                )['Tags']
                if any(t['Key'] == 'managedBy' and t['Value'] == 'ControlTower' for t in tags):
                    skipped.add((name, arn, "Control Tower"))
                    return None

                # Check management account provisioning
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

                return (name, {
                    'Arn': arn,
                    'Description': desc_response['PermissionSet'].get('Description', ''),
                    # Added default PT1H
                    'SessionDuration': desc_response['PermissionSet'].get('SessionDuration', '')
                })

            except Exception as e:
                logger.error(f"Error processing {arn}: {str(e)}")
                return None

        with ThreadPoolExecutor(max_workers=GENERAL_WORKERS) as executor:
            futures = [executor.submit(process_perm_set, arn)
                       for arn in all_arns]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    name, details = result
                    permission_sets[name] = details

        # Log skipped permission sets
        for name, arn, reason in skipped:
            log_skipped_once(name, arn, reason)

        cache.set(cache_key, permission_sets)
        return permission_sets
    except Exception as error:
        logger.error(f"Permission set processing failed: {str(error)}")
        raise


def log_skipped_once(name, arn, reason):
    """Warn once per permission set"""
    global skipped_perm_set
    if name not in skipped_perm_set:
        logger.warning(f"Skipping {name} (managed by {reason})")
        skipped_perm_set.update({arn: name})


def get_provisioned_accounts(perm_set_arn):
    """Get accounts for permission set with caching"""
    cache_key = f"provisioned_{perm_set_arn}"
    cached_provisioned_list = cache.get(cache_key)
    if cached_provisioned_list is not None:
        return cached_provisioned_list

    accounts = []
    try:
        paginator = ic_admin.get_paginator(
            'list_accounts_for_provisioned_permission_set')
        for page in paginator.paginate(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        ):
            accounts.extend(page['AccountIds'])

        cache.set(cache_key, accounts)
        return accounts
    except Exception as e:
        logger.error(f"Failed to get provisioned accounts: {str(e)}")
        raise


@lru_cache(maxsize=1028)
def is_control_tower_managed(perm_set_arn):
    """Check if permission set is managed by Control Tower"""
    try:
        tags = ic_admin.list_tags_for_resource(
            InstanceArn=ic_instance_arn,
            ResourceArn=perm_set_arn
        )['Tags']
        return any(t['Key'] == 'managedBy' and t['Value'] == 'ControlTower' for t in tags)
    except Exception as e:
        logger.error(f"Failed to check Control Tower status: {str(e)}")
        return False


def get_all_json_files(bucket_name):
    """Download all JSON files from S3 bucket"""
    file_contents = {}
    try:
        for s3_object in s3.Bucket(bucket_name).objects.filter(Prefix="permission-sets/"):
            if s3_object.key.endswith('.json'):
                logger.info("Processing file: %s", s3_object.key)
                try:
                    s3.Bucket(bucket_name).download_file(
                        s3_object.key, "/tmp/each_permission_set.json")
                    with open("/tmp/each_permission_set.json") as f:
                        file_contents[s3_object.key] = json.load(f)
                except json.JSONDecodeError as json_error:
                    logger.error(
                        f'Error decoding JSON in file {s3_object.key}: {json_error}')
                except Exception as error:
                    logger.error(
                        f'Cannot load permission set content from file {s3_object.key}: {error}')
    except Exception as error:
        logger.error(
            f'Cannot load permission set content from s3 file: {error}')
    return file_contents


def create_permission_set(name, desc, tags, session_duration):
    """Create a permission set in AWS IAM Identity Center"""
    logger.info(f"Creating permission set: {name}")
    try:
        response = ic_admin.create_permission_set(
            Name=name,
            Description=desc,
            InstanceArn=ic_instance_arn,
            SessionDuration=session_duration,
            Tags=tags
        )
    except ic_admin.exceptions.ConflictException as error:
        logger.info("%sThe same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
        sleep(0.5)
    except ClientError as error:
        error_message = f'Client error occurred: {error}'
        log_and_append_error(error_message)
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)
    cache.set(f"permsets_{delegated}", None)
    return response


def add_managed_policy_to_perm_set(local_name, perm_set_arn, managed_policy_arn):
    """Attach a managed policy to a permission set"""
    logger.info(
        f"Attaching managed policy {managed_policy_arn} to permission set: {local_name} - {perm_set_arn}")
    try:
        attach_managed_policy = ic_admin.attach_managed_policy_to_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn,
            ManagedPolicyArn=managed_policy_arn
        )
        logger.info(
            f'Managed Policy  {managed_policy_arn} to {local_name} - {perm_set_arn}')
    except ic_admin.exceptions.ConflictException as error:
        logger.warning(
            "%s.The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
    except ClientError as error:
        error_message = f'Client error occurred: {error}'
        log_and_append_error(error_message)
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)
    return attach_managed_policy


def remove_managed_policy_from_perm_set(local_name, perm_set_arn, managed_policy_arn):
    """Remove a managed policy from a permission set"""
    logger.info(
        f"Removing managed policy {managed_policy_arn} from permission set: {local_name} - {perm_set_arn}")
    try:
        remove_managed_policy = ic_admin.detach_managed_policy_from_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn,
            ManagedPolicyArn=managed_policy_arn
        )
        logger.info(
            f'Managed Policy {managed_policy_arn} removed from {local_name} - {perm_set_arn}')
    except ic_admin.exceptions.ConflictException as error:
        logger.warning(
            "%s.The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
    except ClientError as error:
        error_message = f'Client error occurred: {error}'
        log_and_append_error(error_message)
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)
    return remove_managed_policy


def add_cx_managed_policy_to_perm_set(local_name, perm_set_arn, policy_name,
                                      policy_path):
    """Attach a customer managed policy to a permission set"""
    logger.info(
        f'Adding Customer Managed Policiy {policy_name} and {policy_path }for Permission Set {local_name}')
    try:
        attach_cx_managed_policy = ic_admin.attach_customer_managed_policy_reference_to_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn,
            CustomerManagedPolicyReference={
                'Name': policy_name,
                'Path': policy_path
            }
        )
        logger.info('Customer Managed Policy %s added to %s', policy_path,
                    local_name)
    except ic_admin.exceptions.ConflictException as error:
        logger.warning(
            "%s.The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
    except ClientError as error:
        error_message = f'Client error occurred: {error}'
        log_and_append_error(error_message)
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)
    return attach_cx_managed_policy


def remove_cx_managed_policy_from_perm_set(local_name, perm_set_arn, policy_name, policy_path):
    """Remove a customer managed policy from a permission set"""
    logger.info(
        f'Removing Customer Managed Policy {policy_name} at {policy_path} for Permission Set: {local_name}')
    try:
        remove_cx_managed_policy = ic_admin.detach_customer_managed_policy_reference_from_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn,
            CustomerManagedPolicyReference={
                'Name': policy_name,
                'Path': policy_path
            }
        )
        logger.info('Managed Policy %s removed \
                    from %s', policy_name, local_name)
    except ic_admin.exceptions.ConflictException as error:
        logger.info("%s.The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
    except ClientError as error:
        error_message = f'Client error occurred: {error}'
        log_and_append_error(error_message)
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)
    return remove_cx_managed_policy


def sync_managed_policies(local_name, local_managed_policies, perm_set_arn):
    """Synchronize Managed Policies using set operations."""
    logger.info(f'Syncing AWS Managed Policies for {local_name}')

    aws_policies = execute_with_retry(
        ic_admin.list_managed_policies_in_permission_set,
        InstanceArn=ic_instance_arn,
        PermissionSetArn=perm_set_arn
    )['AttachedManagedPolicies']
    aws_policy_map = {p['Name']: p['Arn'] for p in aws_policies}
    aws_names = set(aws_policy_map.keys())

    local_policy_map = {p['Name']: p['Arn'] for p in local_managed_policies}
    local_names = set(local_policy_map.keys())

    to_add = local_names - aws_names
    to_remove = aws_names - local_names

    with ThreadPoolExecutor(max_workers=GENERAL_WORKERS) as executor:
        # Add new policies
        for name in to_add:
            executor.submit(
                execute_with_retry,
                add_managed_policy_to_perm_set,
                local_name, perm_set_arn, local_policy_map[name]
            )
        # Remove obsolete policies
        for name in to_remove:
            executor.submit(
                execute_with_retry,
                remove_managed_policy_from_perm_set,
                local_name, perm_set_arn, aws_policy_map[name]
            )


def sync_customer_policies(local_name, local_customer_policies, perm_set_arn):
    """Sync customer-managed policies using set operations."""
    logger.info(f'Syncing Customer Policies for {local_name}')

    aws_policies = execute_with_retry(
        ic_admin.list_customer_managed_policy_references_in_permission_set,
        InstanceArn=ic_instance_arn,
        PermissionSetArn=perm_set_arn
    )['CustomerManagedPolicyReferences']
    aws_policy_set = {(p['Name'], p['Path']) for p in aws_policies}

    local_policy_set = {(p['Name'], p['Path'])
                        for p in local_customer_policies}

    to_add = local_policy_set - aws_policy_set
    to_remove = aws_policy_set - local_policy_set

    with ThreadPoolExecutor(max_workers=GENERAL_WORKERS) as executor:
        for name, path in to_add:
            executor.submit(
                add_cx_managed_policy_to_perm_set,
                local_name, perm_set_arn, name, path
            )
        for name, path in to_remove:
            executor.submit(
                remove_cx_managed_policy_from_perm_set,
                local_name, perm_set_arn, name, path
            )


def get_inline_policy(perm_set_arn):
    cache_key = f"inline_policy_{perm_set_arn}"
    cached_policy = cache.get(cache_key)
    if cached_policy is not None:
        return cached_policy
    try:
        response = ic_admin.get_inline_policy_for_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )
        inline_policy = response.get('InlinePolicy', '{}')
        aws_inline_policy = json.loads(
            inline_policy if inline_policy.strip() else '{}')
        cache.set(cache_key, aws_inline_policy)
        return aws_inline_policy

    except ic_admin.exceptions.ResourceNotFoundException:
        cache.set(cache_key, None)
        return None
    except json.JSONDecodeError:
        logger.warning(
            f"Invalid JSON in existing inline policy for {perm_set_arn}. Treating as empty policy.")
        empty_policy = {}
        cache.set(cache_key, empty_policy)
        return empty_policy


def normalize_policy(policy):
    """Normalize a policy for comparison by parsing and re-serializing with sorted keys"""
    if not policy:
        return {}
    try:
        if isinstance(policy, str):
            policy = json.loads(policy)
        return json.loads(json.dumps(policy, sort_keys=True))
    except json.JSONDecodeError:
        logger.warning(f"Invalid JSON received for normalizing policy")
        return {}


def sync_inline_policies(local_name, local_inline_policy, perm_set_arn):
    """Synchronize Inline Policies as define in the JSON file with AWS"""
    logger.info(
        f"Syncing inline policies for permission set: {local_name} - {perm_set_arn}")
    cache_key = f"inline_policy_{perm_set_arn}"

    if local_inline_policy:
        try:
            aws_inline_policy = get_inline_policy(perm_set_arn)

            if aws_inline_policy:
                normalized_existing = normalize_policy(aws_inline_policy)
                normalized_local = normalize_policy(local_inline_policy)

                if normalized_existing == normalized_local:
                    logger.debug('Inline policy already exists and matches for %s',
                                 local_name)
                    return
            logger.info('Creating inline policy for %s',
                        local_name)
            execute_with_retry(
                ic_admin.put_inline_policy_to_permission_set,
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                InlinePolicy=json.dumps(local_inline_policy)
            )
            cache.set(cache_key, local_inline_policy)
        except ic_admin.exceptions.ConflictException as error:
            logger.warning(
                "%s.The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
        except ClientError as error:
            logger.warning("%s", error)
        except Exception as error:
            error_message = f'Error occurred: {error}'
            log_and_append_error(error_message)
    else:
        # remove inline policy
        try:
            aws_inline_policy = get_inline_policy(perm_set_arn)
            if aws_inline_policy:
                logger.info('Removing inline policy from %s', local_name)
                execute_with_retry(
                    ic_admin.delete_inline_policy_from_permission_set,
                    InstanceArn=ic_instance_arn,
                    PermissionSetArn=perm_set_arn
                )
                cache.delete(cache_key)
            else:
                logger.debug(
                    'No inline policy exists for %s - skipping removal', local_name)
        except ic_admin.exceptions.ResourceNotFoundException:
            logger.debug(
                'No inline policy found for %s - skipping removal', local_name)
        except ic_admin.exceptions.ConflictException as error:
            logger.warning(
                "Conflict while removing inline policy from %s: %s. "
                "The same process may be running elsewhere.", local_name, error)
        except ClientError as error:
            logger.warning(
                "Error removing inline policy from %s: %s", local_name, error)
        except Exception as error:
            error_message = f'Error removing inline policy from {local_name}: {error}'
            log_and_append_error(error_message)


def put_permissions_boundary(local_name, perm_set_arn, boundary_policy):
    """Attach a permissions boundary to a permission set"""
    logger.info(
        f'Putting Permissions Boundary for Permission Set: {local_name} - {perm_set_arn}')
    try:
        if 'Path' in boundary_policy:
            ic_admin.put_permissions_boundary_to_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                PermissionsBoundary={
                    'CustomerManagedPolicyReference': {
                        'Name': boundary_policy['Name'],
                        'Path': boundary_policy['Path']
                    }
                }
            )
        else:
            ic_admin.put_permissions_boundary_to_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                PermissionsBoundary={
                    'ManagedPolicyArn': boundary_policy['Arn']
                }
            )
    except ClientError as error:
        error_message = f'Error attaching permission boundary for Permission Set {local_name} - {perm_set_arn}: {error}'

        log_and_append_error(error_message)
    except Exception as error:
        error_message = f'Error occurred: {error}'

        log_and_append_error(error_message)


def delete_permissions_boundary(local_name, perm_set_arn):
    """Remove permissions boundary from a permission set"""
    logger.info(
        f'Deleting Permissions Boundary for Permission Set: {local_name} - {perm_set_arn}')
    try:
        ic_admin.delete_permissions_boundary_from_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )
    except ClientError as error:
        error_message = f'Error removing permission boundary from Permission Set {local_name} - {perm_set_arn}: {error}'

        log_and_append_error(error_message)
    except Exception as error:
        error_message = f'Error occurred: {error}'

        log_and_append_error(error_message)


def sync_permissions_boundary(local_name, local_boundary, perm_set_arn):
    """Sync permissions boundary configuration"""
    logger.info(
        f'Syncing Permissions Boundary for Permission Set: {local_name} - {perm_set_arn}')
    try:
        current_boundary = None
        current_type = None
        try:
            boundary_info = ic_admin.get_permissions_boundary_for_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn
            ).get('PermissionsBoundary', {})

            if 'ManagedPolicyArn' in boundary_info:
                current_boundary = boundary_info['ManagedPolicyArn']
                current_type = 'MANAGED_POLICY'
            elif 'CustomerManagedPolicyReference' in boundary_info:
                current_boundary = boundary_info['CustomerManagedPolicyReference']
                current_type = 'CUSTOMER_MANAGED_POLICY'
        except ic_admin.exceptions.ResourceNotFoundException:
            pass

        if local_boundary:
            # Check if permission boundary configuration has changed
            needs_update = False
            if current_type == 'MANAGED_POLICY':
                needs_update = current_boundary != local_boundary.get('Arn')
            elif current_type == 'CUSTOMER_MANAGED_POLICY':
                needs_update = (current_boundary.get('Name') != local_boundary.get('Name') or
                                current_boundary.get('Path') != local_boundary.get('Path'))
            else:
                needs_update = True

            if needs_update:
                if current_boundary:
                    delete_permissions_boundary(local_name, perm_set_arn)
                put_permissions_boundary(
                    local_name, perm_set_arn, local_boundary)
        elif current_boundary:
            delete_permissions_boundary(local_name, perm_set_arn)

    except ClientError as error:
        error_message = f'Error syncing permission boundary: {error}'
        log_and_append_error(error_message)
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)


def sync_description(local_name, perm_set_arn, local_desc, aws_desc):
    """Synchronize the description between the JSON file and AWS service"""
    logger.info(
        f'Syncing description for Permission Set: {local_name} - {perm_set_arn}')
    if not local_desc == aws_desc:
        try:
            logger.info('Updating description for %s - %s',
                        local_name, perm_set_arn)
            ic_admin.update_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                Description=local_desc
            )
        except ClientError as error:
            logger.warning("%s", error)
        except Exception as error:
            error_message = f'Error occurred: {error}'
            log_and_append_error(error_message)


def sync_session_duration(local_name, perm_set_arn, aws_session_duration, session_duration):
    """Synchronize the session duration between the JSON file and AWS service"""
    logger.info(
        f'Syncing Session duration for Permission Set: {local_name} - {perm_set_arn}')

    if not session_duration == aws_session_duration:
        try:
            logger.info('Updating session duration for %s - %s',
                        local_name, perm_set_arn)
            ic_admin.update_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                SessionDuration=session_duration
            )
        except ClientError as error:
            logger.warning("%s", error)
        except Exception as error:
            error_message = f'Error occurred: {error}'
            log_and_append_error(error_message)


def sync_tags(local_name, local_tags, perm_set_arn):
    """Sync tags using set operations."""
    logger.info(f'Syncing tags for {local_name}')

    # Fetch current tags
    aws_tags = execute_with_retry(
        ic_admin.list_tags_for_resource,
        InstanceArn=ic_instance_arn,
        ResourceArn=perm_set_arn
    )['Tags']
    aws_tag_set = {(t['Key'], t['Value']) for t in aws_tags}
    local_tag_set = {(t['Key'], t['Value']) for t in local_tags}

    # Tags to add/remove
    tags_to_add = [{'Key': k, 'Value': v}
                   for (k, v) in (local_tag_set - aws_tag_set)]
    tags_to_remove = [k for (k, _) in (aws_tag_set - local_tag_set)]

    # Apply changes
    if tags_to_add:
        execute_with_retry(
            ic_admin.tag_resource,
            InstanceArn=ic_instance_arn,
            ResourceArn=perm_set_arn,
            Tags=tags_to_add
        )
    for key in tags_to_remove:
        execute_with_retry(
            ic_admin.untag_resource,
            InstanceArn=ic_instance_arn,
            ResourceArn=perm_set_arn,
            TagKeys=[key]
        )


@lru_cache(maxsize=1028)
def is_account_active(account_id):
    """Check if the AWS account is active (not suspended or pending closure)"""
    try:
        response = orgs_client.describe_account(AccountId=account_id)
        if response['Account']['Status'] == 'ACTIVE':
            return True
    except Exception as error:
        logger.warning(
            f"Error checking account status for {account_id}: {error}")
        return False


def start_automation():
    logger.debug(f"Delegated: {delegated}")
    delegated_admin = delegated == 'true'
    try:
        logger.info("The automation process is now started.")

        logger.info("Starting the automation process...")
        aws_permission_sets = get_all_permission_sets(delegated_admin)

        if skipped_perm_set:
            try:
                sync_table_for_skipped_perm_sets(skipped_perm_set)
            except Exception as error:
                error_message = f'Failed to invoke sync_table_for_skipped_perm_sets: {error}'
                log_and_append_error(error_message)
        local_files = get_all_json_files(ic_bucket_name)

        # Process sync
        sync_json_with_aws(local_files, aws_permission_sets)

        logger.info("Execution completed! \
                    Check the auto permission set function logs for further execution details.")
        logger.info(f'Codebuild logs contain combined logs for the build project.\
                If you wish to view the logs for just the auto-permissionSet function, you can check out CloudWatch logs: "{permission_set_automation_log_group}/[buildId]-{build_id}"\
                    https://{runtime_region}.console.aws.amazon.com/cloudwatch/home?region={runtime_region}#logsV2:log-groups/log-group/{permission_set_automation_log_group}/log-events/[buildId]-{build_id}')

    except Exception as error:
        error_message = f'Exception occurred: {error}'
        log_and_append_error(error_message)


# @profile(stdout=False, filename='profile_permission_sets.prof')
def main(event=None):
    """
    Main function to handle Pipeline triggered and EventBridge triggered events for permission set automation.
    """

    global errors
    errors = []

    logger.info('Boto3 version: %s', boto3.__version__)
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
                    # event_source = os.getenv("EVENT_SOURCE")
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

        # Start automation
        logger.debug(f"Delegated: {delegated}")
        delegated_admin = delegated == 'true'
        try:
            logger.info("Starting the automation process...")

            aws_permission_sets = get_all_permission_sets(delegated_admin)

            if skipped_perm_set:
                try:
                    sync_table_for_skipped_perm_sets(skipped_perm_set)
                except Exception as error:
                    error_message = f'Failed to invoke sync_table_for_skipped_perm_sets: {error}'
                    log_and_append_error(error_message)
            local_files = get_all_json_files(ic_bucket_name)

            # Process sync
            sync_json_with_aws(local_files, aws_permission_sets)

            logger.info("Execution completed! \
                        Check the auto permission set function logs for further execution details.")
            logger.info(f'Codebuild logs contain combined logs for the build project.\
                    If you wish to view the logs for just the auto-permissionSet function, you can check out CloudWatch logs: "{permission_set_automation_log_group}/[buildId]-{build_id}"\
                        https://{runtime_region}.console.aws.amazon.com/cloudwatch/home?region={runtime_region}#logsV2:log-groups/log-group/{permission_set_automation_log_group}/log-events/[buildId]-{build_id}')

        except Exception as error:
            error_message = f'Exception occurred: {error}'
            log_and_append_error(error_message)
        # cache.print_stats()
        if errors:
            logger.error(f'All Errors during execution: {errors}')
            logger.info("Execution is complete.")
            sys.exit(1)  # Signal failure to CodeBuild
        else:
            logger.info("Execution is complete.")

    except Exception as error:
        error_message = f'Exception occurred: {error}'

        log_and_append_error(error_message)
        if errors:
            logger.error(f'Errors during execution: {errors}')
            sys.exit(1)


if __name__ == "__main__":
    logger.info(f'Codebuild logs contain combined logs for the build project.\
                If you wish to view the logs for just the auto-permissionSet function, you can check out CloudWatch logs: "{permission_set_automation_log_group}/[buildId]-{build_id}"\
                    https://{runtime_region}.console.aws.amazon.com/cloudwatch/home?region={runtime_region}#logsV2:log-groups/log-group/{permission_set_automation_log_group}/log-events/[buildId]-{build_id}')
    main(event)
    # Flush and close watchtower
    watchtower_handler.flush()
    watchtower_handler.close()
