"""Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved"""
# pylint: disable=C0301
# pylint: disable=W1202,W0703
# pylint: disable=E0401
from time import sleep
import json
import os
import logging
import sys
import subprocess
import traceback
import watchtower
from botocore.config import Config
import boto3
from botocore.exceptions import ClientError
# from profilehooks import profile
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
from functools import lru_cache
import time
# from threading import Lock
from weakref import WeakValueDictionary
# from threading import RLock

PERMISSION_WORKERS = 10  # For create/delete operations
GENERAL_WORKERS = 10     # For read/list operations
RETRY_BASE_DELAY = 1     # Base delay for exponential backoff

AWS_CONFIG = Config(
    retries=dict(
        max_attempts=100,
        mode='adaptive'
    ),
    max_pool_connections=PERMISSION_WORKERS + GENERAL_WORKERS
)

runtime_region = os.getenv('AWS_REGION')
ic_bucket_name = os.getenv('IC_S3_BucketName')
s3 = boto3.resource('s3', config=AWS_CONFIG)
orgs_client = boto3.client(
    'organizations', region_name=runtime_region, config=AWS_CONFIG)
sns_client = boto3.client('sns', region_name=runtime_region, config=AWS_CONFIG)
ic_admin = boto3.client(
    'sso-admin', region_name=runtime_region, config=AWS_CONFIG)
ic_instance_arn = os.getenv('IC_InstanceArn')
default_session_duration = 'PT1H'
management_account_id = os.getenv('Org_Management_Account')
delegated = os.getenv('AdminDelegated')
dynamodb = boto3.client(
    'dynamodb', region_name=runtime_region, config=AWS_CONFIG)
logs_client = boto3.client(
    'logs', region_name=runtime_region, config=AWS_CONFIG)
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


# class LockManager:
#     def __init__(self):
#         self.locks = WeakValueDictionary()
#         self._lock = Lock()

#     def get_lock(self, key):
#         with self._lock:
#             if key not in self.locks:
#                 self.locks[key] = Lock()
#             return self.locks[key]


# lock_manager = LockManager()

CACHE_TTL = 1800  # 30 minutes


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


def is_retryable_error(error):
    if isinstance(error, ClientError):
        code = error.response['Error']['Code']
        return code in ['ThrottlingException', 'RequestLimitExceeded']
    return False


def execute_with_retry(func, *args, **kwargs):
    """Enhanced retry helper with custom configurations"""

    retry_kwargs = {
        'max_attempts': kwargs.pop('max_attempts', 5),
        'extra_retry_codes': kwargs.pop('extra_retry_codes', []) + ['ThrottlingException', 'ConflictException'],
        'min_delay': kwargs.pop('min_delay', 1)
    }

    max_attempts = retry_kwargs['max_attempts']
    extra_retry_codes = retry_kwargs['extra_retry_codes']
    min_delay = retry_kwargs['min_delay']
    # max_attempts = kwargs.pop('max_attempts', 5)
    # extra_retry_codes = kwargs.pop('extra_retry_codes', [])
    # extra_retry_codes += ['ThrottlingException', 'ConflictException']
    # min_delay = kwargs.pop('min_delay', 1)

    for attempt in range(max_attempts):
        try:
            return func(*args, **kwargs)
        except (ClientError, ic_admin.exceptions.ConflictException) as error:
            error_code = error.response['Error']['Code']
            if attempt == max_attempts - 1 or error_code not in ['ConflictException'] + extra_retry_codes:
                raise

            base_delay = RETRY_BASE_DELAY * (2 ** attempt)
            sleep_time = max(min_delay, base_delay) + random.uniform(0, 1)

            logger.warning(
                f"Retrying {func.__name__} in {sleep_time:.2f}s (attempt {attempt + 1})")
            sleep(sleep_time)
        except Exception as error:
            log_and_append_error(
                f"Unexpected error in {func.__name__}: {str(error)}")
            raise


def process_permission_set(local_perm_set, aws_permission_sets):
    """Process a single permission set in parallel"""
    local_errors = []
    perm_set_name = local_perm_set['Name']
    local_description = local_perm_set.get('Description', '')
    local_tags = local_perm_set.get('Tags', [])
    local_session_duration = local_perm_set.get('Session_Duration', 'PT1H')

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

    except Exception as e:
        if is_retryable_error(e):
            raise
        local_errors.append(f"{perm_set_name} processing failed: {str(e)}")

    # Sync permission set components
    components = [
        ('ManagedPolicies', sync_managed_policies),
        ('CustomerPolicies', sync_customer_policies),
        ('InlinePolicies', sync_inline_policies),
        ('PermissionsBoundary', sync_permissions_boundary),
        ('Tags', sync_tags)
    ]
    for key, func in components:
        if key in local_perm_set:
            try:
                execute_with_retry(func, perm_set_name,
                                   local_perm_set[key], perm_set_arn)
            except Exception as e:
                local_errors.append(
                    f"{perm_set_name} {key} sync failed: {str(e)}")
    # Sync permission set attributes
    try:
        sync_description(perm_set_name, perm_set_arn,
                         local_description, aws_description)
    except Exception as e:
        log_and_append_error(
            f"{perm_set_name} description sync failed: {str(e)}")
    try:
        sync_session_duration(perm_set_name,
                              perm_set_arn, aws_session_duration, local_session_duration)
    except Exception as e:
        log_and_append_error(
            f"{perm_set_name} session duration sync failed: {str(e)}")

    # Reprovision if needed
    if not local_errors:
        execute_with_retry(reprovision_permission_sets,
                           perm_set_name, perm_set_arn)

    return local_errors


def delete_obsolete_permission_sets(local_files, aws_permission_sets):
    """Delete permission sets that exist in AWS but not in the local configuration"""
    all_errors = []

    # Get the list of local permission set names
    local_perm_set_names = {ps['Name'] for ps in local_files.values()}

    # Find permission sets to delete
    to_delete = [
        (name, aws_permission_sets[name]['Arn'])
        for name in aws_permission_sets
        if name not in local_perm_set_names
    ]

    # Delete in parallel
    with ThreadPoolExecutor(max_workers=PERMISSION_WORKERS) as executor:
        futures = []
        for name, arn in to_delete:
            futures.append(executor.submit(
                delete_permission_set,
                arn,
                name
            ))

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                all_errors.append(f"Delete failed: {str(e)}")

    return all_errors


def sync_table_for_skipped_perm_sets(skipped_perm_set):
    """Sync DynamoDB table with the list of skipped permission sets if Admin is delegated"""
    logger.info("Starting sync of skipped permission sets with DynamoDB table")
    try:
        logger.info(
            "Scanning DynamoDB table for existing skipped permission sets")
        response = dynamodb.scan(
            TableName='ic-SkippedPermissionSetsTable')
        items = response['Items']
        logger.info(f"Items in DynamoDB table: {json.dumps(items, indent=2)}")
        for item in items:
            # If the permission set is not in the current skipped_perm_set, delete it from the table
            if item['perm_set_arn']['S'] not in skipped_perm_set:
                dynamodb.delete_item(
                    TableName='ic-SkippedPermissionSetsTable',
                    Key={'perm_set_arn': item['perm_set_arn']}
                )
                logger.info(
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
    """Unified permission set fetcher with caching"""
    cache_key = f"permsets_{delegated_admin}"
    cached = cache.get(cache_key)
    if cached:
        logger.debug("Using cached permission sets")
        return cached
    permission_sets = {}
    try:
        paginator = ic_admin.get_paginator('list_permission_sets')
        for page in paginator.paginate(InstanceArn=ic_instance_arn):
            for arn in page['PermissionSets']:
                desc = ic_admin.describe_permission_set(
                    InstanceArn=ic_instance_arn,
                    PermissionSetArn=arn
                )['PermissionSet']

                if delegated_admin and management_account_id in get_provisioned_accounts(arn):
                    log_skipped_once(desc['Name'], arn, "management account")
                    continue

                if is_control_tower_managed(arn):
                    log_skipped_once(desc['Name'], arn, "Control Tower")
                    continue

                permission_sets[desc['Name']] = {
                    'Arn': arn, 'Description': desc.get('Description', ''), 'SessionDuration': desc.get('SessionDuration', 'PT1H')}

        cache.set(cache_key, permission_sets)
        return permission_sets
    except Exception as e:
        errors.append(f"Failed to list permission sets: {str(e)}")


def log_skipped_once(name, arn, reason):
    """Warn once per permission set"""
    global skipped_perm_set
    if name not in skipped_perm_set:
        logger.warning(f"Skipping {name} (managed by {reason})")
        skipped_perm_set.update({arn: name})


def get_provisioned_accounts(perm_set_arn):
    """Get accounts for permission set with caching"""
    cache_key = f"provisioned_{perm_set_arn}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    accounts = []
    paginator = ic_admin.get_paginator(
        'list_accounts_for_provisioned_permission_set')
    for page in paginator.paginate(
        InstanceArn=ic_instance_arn,
        PermissionSetArn=perm_set_arn
    ):
        accounts.extend(page['AccountIds'])

    cache.set(cache_key, accounts)
    return accounts


@lru_cache(maxsize=128)
def is_control_tower_managed(perm_set_arn):
    """Check Control Tower tag"""
    tags = execute_with_retry(
        ic_admin.list_tags_for_resource,
        InstanceArn=ic_instance_arn,
        ResourceArn=perm_set_arn
    )['Tags']
    return any(t['Key'] == 'managedBy' and t['Value'] == 'ControlTower' for t in tags)


def get_all_json_files(bucket_name):
    """Download all the JSON files from IAM Identity Center S3 bucket"""
    logger.info("Getting all json files from S3 bucket")
    file_contents = {}
    my_bucket = s3.Bucket(bucket_name)
    try:
        for s3_object in my_bucket.objects.filter(Prefix="permission-sets/"):
            if ".json" in s3_object.key:
                file_name = s3_object.key
                logger.info("processing file: %s", file_name)
                try:
                    s3.Bucket(bucket_name).download_file(
                        file_name, "/tmp/each_permission_set.json")
                    temp_file = open("/tmp/each_permission_set.json")
                    data = json.load(temp_file)
                    file_contents[file_name] = data
                    logger.debug("File data: %s", data)
                    temp_file.close()
                except json.JSONDecodeError as json_error:
                    error_message = f'Error decoding JSON in file {file_name}: {json_error}'
                    log_and_append_error(error_message)
                except Exception as error:
                    error_message = f'Cannot load permission set content from file {file_name}: {error}'
                    log_and_append_error(error_message)
    except Exception as error:
        error_message = f'Cannot load permission set content from s3 file: {error}'
        log_and_append_error(error_message)
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
        logger.info('Managed Policy %s added to %s',
                    managed_policy_arn, perm_set_arn)
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
        logger.info('Managed Policy %s removed \
                    from %s', managed_policy_arn, perm_set_arn)
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
    """
    Synchronize Managed Policies as defined in the JSON file with AWS
    Declare arrays for keeping track on Managed policies locally and on AWS
    """
    aws_managed_attached_names = []
    aws_managed_attached_dict = {}
    local_policy_names = []
    local_policy_dict = {}

    logger.info(
        f'Syncing AWS Managed Policies for Permission Set: {local_name}')

    # Get all the managed policies attached to the permission set.
    try:
        list_managed_policies = ic_admin.list_managed_policies_in_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )
        # Populate arrays to track Managed Policy
        for aws_managed_policy in list_managed_policies['AttachedManagedPolicies']:
            aws_managed_attached_names.append(aws_managed_policy['Name'])
            aws_managed_attached_dict[aws_managed_policy['Name']
                                      ] = aws_managed_policy['Arn']

        for local_managed_policy in local_managed_policies:
            local_policy_names.append(local_managed_policy['Name'])
            local_policy_dict[local_managed_policy['Name']
                              ] = local_managed_policy['Arn']

        for policy_name in local_policy_names:
            if not policy_name in aws_managed_attached_names:
                add_managed_policy_to_perm_set(
                    local_name, perm_set_arn, local_policy_dict[policy_name])

        for aws_policy in aws_managed_attached_names:
            if not aws_policy in local_policy_names:
                remove_managed_policy_from_perm_set(local_name, perm_set_arn,
                                                    aws_managed_attached_dict[aws_policy])

    except ic_admin.exceptions.ConflictException as error:
        logger.warning(
            "%s.The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
        sleep(0.5)
    except Exception as error:
        error_message = f'Exception occurred: {error}'
        log_and_append_error(error_message)


def sync_customer_policies(local_name, local_customer_policies, perm_set_arn):
    """
    Synchronize customer managed policies as defined in the JSON file with AWS
    Declare arrays for keeping track on custom policies locally and on AWS
    """
    customer_managed_attached_names = []
    customer_managed_attached_dict = {}
    local_policy_names = []
    local_policy_dict = {}

    logger.info(
        f'Syncing Customer Managed Policies for Permission Set: {local_name}')

    # Get all the customer managed policies attached to the permission set.
    try:
        list_cx_managed_policies = ic_admin.list_customer_managed_policy_references_in_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )
        for cx_managed_policy in list_cx_managed_policies['CustomerManagedPolicyReferences']:
            customer_managed_attached_names.append(cx_managed_policy['Name'])
            customer_managed_attached_dict[cx_managed_policy['Name']
                                           ] = cx_managed_policy['Path']

        for local_managed_policy in local_customer_policies:
            local_policy_names.append(local_managed_policy['Name'])
            local_policy_dict[local_managed_policy['Name']
                              ] = local_managed_policy['Path']

        for policy_name, policy_path in local_policy_dict.items():
            if not policy_name in customer_managed_attached_names:
                logger.debug(
                    f'Local policy {policy_name} found in attached customer policy in permission set')
                add_cx_managed_policy_to_perm_set(local_name, perm_set_arn, policy_name,
                                                  policy_path)

        for ex_policy_name, ex_policy_path in customer_managed_attached_dict.items():
            if not ex_policy_name in local_policy_names:
                logger.info(
                    f'Attached customer managed policy {ex_policy_name} found in local JSON ')
                remove_cx_managed_policy_from_perm_set(local_name, perm_set_arn, ex_policy_name,
                                                       ex_policy_path)
    except ic_admin.exceptions.ConflictException as error:
        logger.warning(
            "%s.The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
        sleep(0.5)
    except Exception as error:
        error_message = f'Exception occurred: {error}'
        log_and_append_error(error_message)


def remove_inline_policies(local_name, perm_set_arn):
    """Remove Inline policies from permission set if they exist"""
    try:
        list_existing_inline = ic_admin.get_inline_policy_for_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )

        if list_existing_inline['InlinePolicy']:
            logger.info(
                f"Removing inline policies from permission set: {local_name} - {perm_set_arn}")
            ic_admin.delete_inline_policy_from_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn
            )
            logger.info('Removed inline policy for %s - %s',
                        local_name, perm_set_arn)
    except ic_admin.exceptions.ConflictException as error:
        logger.warning(
            "%s.The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
        sleep(0.5)
    except ClientError as error:
        error_message = f'Client error occurred: {error}'
        log_and_append_error(error_message)
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)


def sync_inline_policies(local_name, local_inline_policy, perm_set_arn):
    """Synchronize Inline Policies as define in the JSON file with AWS"""
    logger.info(
        f"Syncing inline policies for permission set: {local_name} - {perm_set_arn}")
    if local_inline_policy:
        try:
            logger.info('Synchronizing inline policy with %s - %s',
                        local_name, perm_set_arn)
            ic_admin.put_inline_policy_to_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                InlinePolicy=json.dumps(local_inline_policy)
            )
        except ic_admin.exceptions.ConflictException as error:
            logger.warning(
                "%s.The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
        except ClientError as error:
            logger.warning("%s", error)
        except Exception as error:
            error_message = f'Error occurred: {error}'
            log_and_append_error(error_message)
    else:
        remove_inline_policies(local_name, perm_set_arn)


def delete_permission_set(perm_set_arn, perm_set_name):
    """Delete IAM Identity Center permission sets"""
    logger.info(f"Deleting permission set: {perm_set_name} ({perm_set_arn})")

    # Check if permission set is managed by Control Tower
    if is_control_tower_managed(perm_set_arn):
        logger.warning(
            f"Cannot delete Control Tower managed permission set: {perm_set_name}")
        return

    # Check if permission set is in use
    accounts = get_provisioned_accounts(perm_set_arn)
    if accounts:
        logger.info(
            f"Deprovisioning {perm_set_name} from {len(accounts)} accounts")
        deprovision_permission_set(perm_set_arn, perm_set_name)

    # Verify deprovisioning completed
    remaining_accounts = get_provisioned_accounts(perm_set_arn)
    if remaining_accounts:
        raise Exception(
            f"Failed to deprovision {perm_set_name} from accounts: {remaining_accounts}")

    try:
        ic_admin.delete_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn)
        logger.info('%s Permission set deleted', perm_set_name)
        cache.set(f"permsets_{delegated}", None)  # Invalidate cache
    except ic_admin.exceptions.ConflictException as error:
        logger.warning(f"Conflict during deletion of {perm_set_name}: {error}")

    except ClientError as error:
        if error.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.info(f"Permission set {perm_set_name} already deleted")
            return

    except Exception as error:
        error_message = f'Unexpected error occurred while deleting {perm_set_name}: {error}'
        log_and_append_error(error_message)


def put_permissions_boundary(local_name, perm_set_arn, boundary_policy):
    """Attach a permissions boundary to a permission set"""
    logger.info(
        f'Putting Permissions Boundary for Permission Set: {local_name} - {perm_set_arn}')
    try:
        if 'Path' in boundary_policy:
            # Customer managed policy
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
            # AWS managed policy
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


def tag_permission_set(local_name, local_tags, perm_set_arn):
    """Add tags to the permission sets"""
    try:
        ic_admin.tag_resource(
            InstanceArn=ic_instance_arn,
            ResourceArn=perm_set_arn,
            Tags=local_tags
        )
        logger.info('Tags added to or updated for %s - %s',
                    local_name, perm_set_arn)
    except ClientError as error:
        error_message = f'Client error occurred: {error}'
        log_and_append_error(error_message)
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)


def remove_tag(key, perm_set_arn, local_name):
    """Remove tags from a permission set"""
    try:
        ic_admin.untag_resource(
            InstanceArn=ic_instance_arn,
            ResourceArn=perm_set_arn,
            TagKeys=[
                key,
            ]
        )
        logger.info('Tag removed from %s - %s', local_name, perm_set_arn)
    except ClientError as error:
        error_message = f'Client error occurred: {error}'
        log_and_append_error(error_message)
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)


def sync_tags(local_name, local_tags, perm_set_arn):
    """Synchronize the tags between the JSON and AWS"""
    cache_key = f"tags_{perm_set_arn}"
    cached_tags = cache.get(cache_key)

    if cached_tags and cached_tags == local_tags:
        logger.debug(f"Skipping tag sync for {local_name} - no changes")
        return
    logger.info(
        f'Syncing tags for Permission Set: {local_name} - {perm_set_arn}')
    try:
        list_tags = ic_admin.list_tags_for_resource(
            InstanceArn=ic_instance_arn,
            ResourceArn=perm_set_arn
        )
        aws_tags = list_tags['Tags']
        aws_tag_keys = []
        aws_tag_dict = {}
        local_tag_keys = []
        local_tag_dict = {}

        for tag in aws_tags:
            aws_tag_keys.append(tag['Key'])
            aws_tag_dict[tag['Key']] = tag['Value']

        for tag in local_tags:
            local_tag_keys.append(tag['Key'])
            local_tag_dict[tag['Key']] = tag['Value']

        if not aws_tags == local_tags:
            for key in local_tag_keys:
                if key not in aws_tag_keys or local_tag_dict[key] != aws_tag_dict[key]:
                    tag_permission_set(local_name, local_tags, perm_set_arn)

            for key in aws_tag_keys:
                if key not in local_tag_keys:
                    remove_tag(key, perm_set_arn, local_name)

    except ClientError as error:
        error_message = f'Client error occurred: {error}'
        log_and_append_error(error_message)
    except Exception as error:
        error_message = f'Error occurred: {error}'
        log_and_append_error(error_message)
    cache.set(cache_key, local_tags)


def get_active_accounts_map():
    """Get a map of all accounts and their active status"""
    account_status_map = {}
    try:
        paginator = orgs_client.get_paginator('list_accounts')
        for page in paginator.paginate():
            for account in page['Accounts']:
                account_status_map[account['Id']
                                   ] = account['Status'] == 'ACTIVE'
        return account_status_map
    except Exception as error:
        logger.warning(f"Error fetching account statuses: {error}")
        return {}


def is_account_active(account_id, account_status_map=None):
    """Check if the AWS account is active (not suspended or pending closure)"""
    if account_status_map is None:
        # If no map is provided, fall back to single account check
        try:
            response = orgs_client.describe_account(AccountId=account_id)
            status = response['Account']['Status']
            return status == 'ACTIVE'
        except Exception as error:
            logger.warning(
                f"Error checking account status for {account_id}: {error}")
            return False

    return account_status_map.get(account_id, False)


def deprovision_permission_set(perm_set_arn, perm_set_name):
    """Deprovision permission sets with batch processing and dynamic retries"""
    logger.info(f'Deprovisioning {perm_set_name}')
    account_ids = get_provisioned_accounts(perm_set_arn)

    if not account_ids:
        logger.info(f"No accounts found for {perm_set_name}")
        return

    # Calculate batch size and max attempts dynamically
    batch_size = calculate_batch_size(len(account_ids))
    max_attempts = dynamic_max_attempts(len(account_ids))

    # Process accounts in batches
    batches = [account_ids[i:i + batch_size]
               for i in range(0, len(account_ids), batch_size)]
    failed_accounts = []

    for batch in batches:
        with ThreadPoolExecutor(max_workers=PERMISSION_WORKERS) as executor:
            # Create future-account mapping
            future_to_account = {
                executor.submit(deprovision_account, perm_set_name, perm_set_arn, account, max_attempts): account
                for account in batch
            }

            for future in as_completed(future_to_account):
                account = future_to_account[future]
                try:
                    if (result := future.result()):
                        failed_accounts.append(result)
                except Exception as error:
                    logger.error(f"Unexpected error for {account}: {error}")
                    failed_accounts.append(account)

    # Retry failed accounts with increased max attempts
    if failed_accounts:
        logger.info(
            f"Retrying failed accounts for {perm_set_name}: {failed_accounts}")
        with ThreadPoolExecutor(max_workers=PERMISSION_WORKERS) as executor:
            future_to_account = {
                executor.submit(deprovision_account, perm_set_name, perm_set_arn, account, max_attempts + 5): account
                for account in failed_accounts
            }

            for future in as_completed(future_to_account):
                account = future_to_account[future]
                try:
                    if (result := future.result()):
                        logger.error(f"Permanent failure for {account}")
                except Exception as error:
                    logger.error(f"Final error for {account}: {error}")

    logger.info(f"Completed deprovisioning for {perm_set_name}")


def deprovision_account(perm_set_name, perm_set_arn, account, max_attempts=7):
    """Handle deprovisioning for a single account"""
    attempt = 0
    while attempt < max_attempts:
        try:
            logger.info(
                f"Deprovisioning {perm_set_name} from {account} (attempt {attempt + 1})")
            # Get all assignments for this account
            acct_assignments = []

            paginator = ic_admin.get_paginator('list_account_assignments')
            for page in paginator.paginate(
                InstanceArn=ic_instance_arn,
                AccountId=account,
                PermissionSetArn=perm_set_arn
            ):
                acct_assignments.extend(page['AccountAssignments'])

            # Delete all assignments
            for assignment in acct_assignments:
                logger.info(
                    f"Deleting assignment for account {account}: {assignment}")
                delete_response = execute_with_retry(
                    ic_admin.delete_account_assignment,
                    InstanceArn=ic_instance_arn,
                    TargetId=account,
                    TargetType='AWS_ACCOUNT',
                    PermissionSetArn=perm_set_arn,
                    PrincipalType=assignment['PrincipalType'],
                    PrincipalId=assignment['PrincipalId'],
                    extra_retry_codes=['ConflictException'],
                    max_attempts=7
                )

                # Wait for deletion to complete
                request_id = delete_response['AccountAssignmentDeletionStatus']['RequestId']
                while True:
                    status_response = ic_admin.describe_account_assignment_deletion_status(
                        InstanceArn=ic_instance_arn,
                        AccountAssignmentDeletionRequestId=request_id
                    )
                    status = status_response['AccountAssignmentDeletionStatus']['Status']

                    if status == 'SUCCEEDED':
                        logger.info(
                            f"Successfully deprovisioned {perm_set_name} from {account}")
                        return None
                    elif status in ['FAILED', 'CANCELLED']:
                        failure_reason = status_response['AccountAssignmentDeletionStatus'].get(
                            'FailureReason', 'Unknown')
                        raise Exception(
                            f"Deprovisioning failed: {failure_reason}")
                    sleep(0.5)

        except Exception as error:
            attempt += 1
            if attempt >= max_attempts:
                logger.error(
                    f"Max deprovision retries exceeded for {account}: {str(error)}")
                return account  # Return failed account for tracking

            base_delay = RETRY_BASE_DELAY * (2 ** attempt)
            sleep_time = min(base_delay + random.uniform(0, 1),
                             30)  # Cap at 30 seconds
            logger.warning(
                f"Retrying deprovision for {account} in {sleep_time:.2f}s (attempt {attempt + 1})")
            sleep(sleep_time)


def provision_account(perm_set_name, perm_set_arn, account, max_attempts=7):
    """Provision a permission set to a single account with dynamic retries"""
    attempt = 0
    while attempt < max_attempts:
        try:
            logger.info(
                f"Provisioning {perm_set_name} for account {account} (attempt {attempt + 1})")

            # Initiate provisioning
            provision_response = ic_admin.provision_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                TargetType='AWS_ACCOUNT',
                TargetId=account
            )

            # Track provisioning status
            request_id = provision_response['PermissionSetProvisioningStatus']['RequestId']
            while True:
                status_response = ic_admin.describe_permission_set_provisioning_status(
                    InstanceArn=ic_instance_arn,
                    ProvisionPermissionSetRequestId=request_id
                )
                status = status_response['PermissionSetProvisioningStatus']['Status']

                if status == 'SUCCEEDED':
                    logger.info(
                        f"Successfully provisioned {perm_set_name} to {account}")
                    return None
                elif status in ['FAILED', 'CANCELLED']:
                    failure_reason = status_response['PermissionSetProvisioningStatus'].get(
                        'FailureReason', 'Unknown')
                    raise Exception(f"Provisioning failed: {failure_reason}")
                sleep(0.5)

        except Exception as error:
            attempt += 1
            if attempt >= max_attempts:
                logger.error(
                    f"Max retries exceeded for {account}: {str(error)}")
                return account  # Return failed account for tracking

            base_delay = RETRY_BASE_DELAY * (2 ** attempt)
            sleep_time = min(base_delay + random.uniform(0, 1),
                             30)  # Cap at 30 seconds
            logger.warning(
                f"Retrying {account} in {sleep_time:.2f}s (attempt {attempt + 1})")
            sleep(sleep_time)


def calculate_batch_size(total_accounts):
    """Dynamically adjust batch size based on total accounts"""
    if total_accounts <= 20:
        return 5
    elif total_accounts <= 100:
        return 10
    else:
        return 15 + (total_accounts // 50)  # Scale with number of accounts


def dynamic_max_attempts(total_accounts):
    """Dynamically adjust max retry attempts based on total accounts"""
    base = 7
    # Max 15 attempts for large deployments
    return min(base + (total_accounts // 20), 15)


def reprovision_permission_sets(perm_set_name, perm_set_arn):
    """Find and re-provision permission sets"""
    logger.info(f'Reprovisioning {perm_set_name}')
    account_ids = get_provisioned_accounts(perm_set_arn)

    if not account_ids:
        logger.info(f"No accounts found for {perm_set_name}")
        return
    outdated_accounts = []
    never_provisioned_accounts = []
    # Check if the permission set is outdated or if it was never provisioned
    for account in account_ids:
        provisioned_perm_sets = []
        try:
            # check if permission set is provisioned
            provisioned_perm_sets = ic_admin.list_permission_sets_provisioned_to_account(
                InstanceArn=ic_instance_arn,
                AccountId=account
            )

            # If permission set not in list, it was never provisioned
            if perm_set_arn not in provisioned_perm_sets.get('PermissionSets', []):
                never_provisioned_accounts.append(account)
                continue

            # Check for outdated permission sets
            outdated_perm_sets = ic_admin.list_permission_sets_provisioned_to_account(
                InstanceArn=ic_instance_arn,
                AccountId=account,
                ProvisioningStatus='LATEST_PERMISSION_SET_NOT_PROVISIONED'
            )
            # If permission set in list, it is outdated
            if perm_set_arn in outdated_perm_sets.get('PermissionSets', []):
                outdated_accounts.append(account)

        except ic_admin.exceptions.ConflictException as error:
            logger.warning(
                "The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts: %s", str(error))
            sleep(0.5)
        except ClientError as error:
            error_msg = str(error)
            error_message = f'Client error occurred during permission set provisioning: {error_msg}'
            log_and_append_error(error_message)
        except Exception as error:
            error_msg = str(error)
            error_message = f'Error occurred during permission set provisioning: {error_msg}'
            log_and_append_error(error_message)

    failed_accounts = []
    # Provision if there are any outdated or non-provisioned permission sets for any accounts
    if outdated_accounts or never_provisioned_accounts:
        logger.info(
            f'Accounts with outdated permission sets: {outdated_accounts if outdated_accounts else "None"} for {perm_set_name}')
        logger.info(
            f'Accounts with non-provisioned permission sets: {never_provisioned_accounts if never_provisioned_accounts else "None"} for {perm_set_name}')
        drifted_account_ids = list(
            set(outdated_accounts + never_provisioned_accounts))

        # Calculate batch size and max attempts dynamically
    batch_size = calculate_batch_size(len(account_ids))
    max_attempts = dynamic_max_attempts(len(account_ids))

    # Process accounts in batches
    batches = [account_ids[i:i + batch_size]
               for i in range(0, len(account_ids), batch_size)]
    failed_accounts = []

    for batch in batches:
        with ThreadPoolExecutor(max_workers=PERMISSION_WORKERS) as executor:
            # Create future-account mapping
            future_to_account = {
                executor.submit(provision_account, perm_set_name, perm_set_arn, account, max_attempts): account
                for account in batch
            }

            for future in as_completed(future_to_account):
                account = future_to_account[future]
                try:
                    if (result := future.result()):
                        failed_accounts.append(result)
                except Exception as error:
                    logger.error(f"Unexpected error for {account}: {error}")
                    failed_accounts.append(account)

    # Retry failed accounts with increased max attempts
    if failed_accounts:
        logger.info(
            f"Retrying failed accounts for {perm_set_name}: {failed_accounts}")
        with ThreadPoolExecutor(max_workers=PERMISSION_WORKERS) as executor:
            future_to_account = {
                executor.submit(provision_account, perm_set_name, perm_set_arn, account, max_attempts + 5): account
                for account in failed_accounts
            }

            for future in as_completed(future_to_account):
                account = future_to_account[future]
                try:
                    if (result := future.result()):
                        logger.error(f"Permanent failure for {account}")
                except Exception as error:
                    logger.error(f"Final error for {account}: {error}")

    logger.info(f"Completed reprovisioning for {perm_set_name}")


def sync_json_with_aws(local_files, aws_permission_sets):
    """Parallelized sync function"""
    all_errors = []

    # Process existing permission sets in parallel
    with ThreadPoolExecutor(max_workers=GENERAL_WORKERS) as executor:
        futures = []
        for local_file in local_files.values():
            futures.append(executor.submit(
                process_permission_set,
                local_file,
                aws_permission_sets
            ))

        for future in as_completed(futures):
            all_errors.extend(future.result())

    # Delete obsolete permission sets
    delete_errors = delete_obsolete_permission_sets(
        local_files, aws_permission_sets)
    all_errors.extend(delete_errors)

    return all_errors


def start_automation():
    logger.debug(f"Delegated: {delegated}")
    delegated_admin = delegated == 'true'
    try:
        logger.info("The automation process is now started.")

        # Get state
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

        start_automation()
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
