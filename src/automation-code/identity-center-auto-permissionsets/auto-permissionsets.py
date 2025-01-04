"""Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved"""
# pylint: disable=C0301
# pylint: disable=W1202,W0703
# pylint: disable=E0401

####################################################################
# A workaround of upgrade the boto3 version during runtime #
####################################################################
# import cfnresponse
from time import sleep
import json
import os
import logging
import sys
import subprocess
import watchtower

# Upgrade boto3 to the latest version
# subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-I', '-q', 'boto3', '--target', '/tmp/',
#                        '--no-cache-dir', '--disable-pip-version-check'])
# sys.path.insert(0, '/tmp/')
import boto3
from botocore.exceptions import ClientError

runtime_region = os.getenv('AWS_REGION')
ic_bucket_name = os.getenv('IC_S3_BucketName')
# pipeline = boto3.client('codepipeline', region_name=runtime_region)
s3 = boto3.resource('s3')
sns_client = boto3.client('sns', region_name=runtime_region)
# sns_topic_name = os.getenv('SNS_Topic_Name')
ic_admin = boto3.client('sso-admin', region_name=runtime_region)
ic_instance_arn = os.getenv('IC_InstanceArn')
default_session_duration = os.getenv('Session_Duration')
management_account_id = os.getenv('Org_Management_Account')
delegated = os.getenv('AdminDelegated')
dynamodb = boto3.client('dynamodb', region_name=runtime_region)
logs_client = boto3.client('logs', region_name=runtime_region)
permission_set_automation_log_group = os.getenv('PermissionSetAutomationLogGroupName')
# build_arn = os.getenv('CODEBUILD_BUILD_ARN')
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

# Stream handler to print logs on screen
console_handler= logging.StreamHandler()
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

def log_and_append_error(message):
    logger.error(message)
    errors.append(message)

logger.info("Logging initialized")

if event_env:
    event = event_env
else:
    event = None

def sync_table_for_skipped_perm_sets(skipped_perm_set):
    """Sync DynamoDB table with the list of skipped permission sets if Admin is delegated"""
    logger.info("Starting sync of skipped permission sets with DynamoDB table")
    try:
        logger.info("Scanning DynamoDB table for existing skipped permission sets")
        response = dynamodb.scan(
            TableName='ic-SkippedPermissionSetsTable')
        items = response['Items']
        logger.info(f"Items in DynamoDB table: {items}")
        for item in items:
            # If the permission set is not in the current skipped_perm_set, delete it from the table
            if item['perm_set_arn']['S'] not in skipped_perm_set:
                dynamodb.delete_item(
                    TableName='ic-SkippedPermissionSetsTable',
                    Key={'perm_set_arn': item['perm_set_arn']}
                )
                logger.info(f"Drift detected in DynamoDB table. Deleted item: {item} from table.")

            sleep(0.1)

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
        #Get all skipped permission sets that were unprocessed
        unprocessed_items = batch.get('UnprocessedItems')
        if unprocessed_items:
            error_message=f"There were unprocessed skipped permission sets while writing to DynamoDB table: {unprocessed_items}"
            # logger.error(error_message)
            log_and_append_error(error_message)
        else:
            logger.info("All skipped permission sets written successfully to the table")
    except dynamodb.exceptions.ThrottlingException as error:
        logger.warning("Hit DynamoDB API limits. Sleep 5s...%s", error)
        sleep(5)
    except ClientError as error:
        error_message=f"Client error occurred: {error}"
        # logger.error(error_message)
        log_and_append_error(error_message)

def get_all_permission_sets():
    """List all the permission sets for the IAM Identity Center ARN"""
    try:
        permission_set_name_and_arn = {}
        response = ic_admin.list_permission_sets(
            InstanceArn=ic_instance_arn,
            MaxResults=100
        )
        all_perm_sets_arns = response['PermissionSets']
        while 'NextToken' in response:
            response = ic_admin.list_permission_sets(
                InstanceArn=ic_instance_arn,
                NextToken=response['NextToken'],
                MaxResults=100
            )
            all_perm_sets_arns += response['PermissionSets']
        global skipped_perm_set
        skipped_perm_set.clear()
        for perm_set_arn in all_perm_sets_arns:
            describe_perm_set = ic_admin.describe_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn
            )
            sleep(0.1)  # Avoid hitting API limit.
            description = ''
            try:
                description = describe_perm_set['PermissionSet'].get('Description', '-')
            except Exception as error:
                error_message=f'Failed to get description for permission set {perm_set_arn}. Error: {error}'
                # logger.error(error_message)
                log_and_append_error(error_message)
                description = 'Error retrieving description'
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
                continue # Ignore permission set if managed by Control Tower. Requires users to tag Control Tower managed permission sets before running the pipeline
            permission_set_name_and_arn[perm_set_name] = {
                'Arn': perm_set_arn,
                'Description': description
                }
    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning("Hit IAM Identity Center API limits. Sleep 5s...%s", error)
        sleep(5)
    except ic_admin.exceptions.ConflictException as error:
        logger.warning("The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...%s", error)
        sleep(2)
    except ClientError as error:
        error_message=f'Client error occurred: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)
    if skipped_perm_set:
        try:
            logger.info(f"Skipped Permission Set Name and ARN: {skipped_perm_set}")
            sync_table_for_skipped_perm_sets(skipped_perm_set)
        except Exception as error:
            error_message=f'Failed to invoke sync_table_for_skipped_perm_sets: {error}'
            # logger.error(error_message)
            log_and_append_error(error_message)
    else:
        logger.info("No Permission Sets were skipped")
    return permission_set_name_and_arn

def get_all_permission_sets_if_delegate():
    """List all the permission sets for the IAM Identity Center ARN"""
    try:
        permission_set_name_and_arn = {}
        response = ic_admin.list_permission_sets(
            InstanceArn=ic_instance_arn,
            MaxResults=100
        )
        all_perm_sets_arns = response['PermissionSets']
        while 'NextToken' in response:
            response = ic_admin.list_permission_sets(
                InstanceArn=ic_instance_arn,
                NextToken=response['NextToken'],
                MaxResults=100
            )
            all_perm_sets_arns += response['PermissionSets']

        global skipped_perm_set
        skipped_perm_set.clear()
        for perm_set_arn in all_perm_sets_arns:
            describe_perm_set = ic_admin.describe_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn
            )
            sleep(0.1)  # Avoid hitting API limit.
            description = ''
            try:
                description = describe_perm_set['PermissionSet']['Description']
            except Exception as error:
                error_message=f'Failed to get description for permission set {perm_set_arn}. Error: {error}'
                # logger.error(error_message)
                log_and_append_error(error_message)
            perm_set_name = describe_perm_set['PermissionSet']['Name']
            perm_set_arn = describe_perm_set['PermissionSet']['PermissionSetArn']
            list_accounts_for_provisioned_perm_set = ic_admin.list_accounts_for_provisioned_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                MaxResults=100,
            )
            accounts_for_perm_set = list_accounts_for_provisioned_perm_set['AccountIds']
            sleep(0.1)  # Avoid hitting API limit.
            while 'NextToken' in list_accounts_for_provisioned_perm_set:
                list_accounts_for_provisioned_perm_set = ic_admin.list_accounts_for_provisioned_permission_set(
                    InstanceArn=ic_instance_arn,
                    PermissionSetArn=perm_set_arn,
                    MaxResults=100,
                    NextToken=list_accounts_for_provisioned_perm_set['NextToken']
                )
                sleep(0.1)  # Avoid hitting API limit.
                accounts_for_perm_set += list_accounts_for_provisioned_perm_set['AccountIds']
            logger.info("Accounts for permission set %s is %s", perm_set_arn, accounts_for_perm_set)
            if management_account_id in accounts_for_perm_set:
                skipped_perm_set.update({perm_set_arn: perm_set_name})
                continue
            permission_set_name_and_arn[perm_set_name] = {
                'Arn': perm_set_arn,
                'Description': description
                }
    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning("Hit IAM Identity Center API limits. Sleep 5s...%s", error)
        sleep(5)
    except ic_admin.exceptions.ConflictException as error:
        logger.warning("The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...%s", error)
        sleep(2)
    except ClientError as error:
        error_message=f'Client error occurred: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)
    if skipped_perm_set:
        try:
            logger.info(f"Skipped Permission Set Name and ARN: {skipped_perm_set}")
            sync_table_for_skipped_perm_sets(skipped_perm_set)
        except Exception as error:
            error_message=f'Failed to invoke sync_table_for_skipped_perm_sets: {error}'
            # logger.error(error_message)
            log_and_append_error(error_message)
    else:
        logger.info("No Permission Sets were skipped")
    return permission_set_name_and_arn


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
                    # logger.error(error_message)
                    log_and_append_error(error_message)
                except Exception as error:
                    error_message = f'Cannot load permission set content from file {file_name}: {error}'
                    # logger.error(error_message)
                    log_and_append_error(error_message)
    except Exception as error:
        error_message=f'Cannot load permission set content from s3 file: {error}'
        # logger.error(error_message)
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
        sleep(0.1)  # Avoid hitting API limit.
    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning("%sHit CreatePermissionSet API limits. Sleep 5s.", error)
        sleep(5)
    except ic_admin.exceptions.ConflictException as error:
        logger.info("%sThe same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
        sleep(2)
    except ClientError as error:
        error_message=f'Client error occurred: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)
    return response


def add_managed_policy_to_perm_set(local_name, perm_set_arn, managed_policy_arn):
    """Attach a managed policy to a permission set"""
    logger.info(f"Attaching managed policy {managed_policy_arn} to permission set: {local_name} - {perm_set_arn}")
    try:
        attach_managed_policy = ic_admin.attach_managed_policy_to_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn,
            ManagedPolicyArn=managed_policy_arn
        )
        logger.info('Managed Policy %s added to %s',
                    managed_policy_arn, perm_set_arn)
        sleep(0.1)  # Avoid hitting API limit.

    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning("%s.Hit API limits. Sleep 2s.", error)
        sleep(2)
    except ic_admin.exceptions.ConflictException as error:
        logger.warning("%s.The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
    except ClientError as error:
        error_message=f'Client error occurred: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)
    return attach_managed_policy


def remove_managed_policy_from_perm_set(local_name, perm_set_arn, managed_policy_arn):
    """Remove a managed policy from a permission set"""
    logger.info(f"Removing managed policy {managed_policy_arn} from permission set: {local_name} - {perm_set_arn}")
    try:
        remove_managed_policy = ic_admin.detach_managed_policy_from_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn,
            ManagedPolicyArn=managed_policy_arn
        )
        logger.info('Managed Policy %s removed \
                    from %s', managed_policy_arn, perm_set_arn)
        sleep(0.1)  # Avoid hitting API limit.
    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning("%s.Hit API limits. Sleep 2s...", error)
        sleep(2)
    except ic_admin.exceptions.ConflictException as error:
        logger.warning("%s.The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
    except ClientError as error:
        error_message=f'Client error occurred: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)
    return remove_managed_policy


def add_cx_managed_policy_to_perm_set(local_name, perm_set_arn, policy_name,
                                      policy_path):
    """Attach a customer managed policy to a permission set"""
    logger.info(f'Adding Customer Managed Policiy {policy_name} and {policy_path }for Permission Set: {local_name}')
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
        sleep(0.1)  # Avoid hitting API limit.

    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning("%s.Hit API limits. Sleep 2s.", error)
        sleep(2)
    except ic_admin.exceptions.ConflictException as error:
        logger.warning("%s.The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
    except ClientError as error:
        error_message=f'Client error occurred: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)
    return attach_cx_managed_policy


def remove_cx_managed_policy_from_perm_set(local_name, perm_set_arn, policy_name, policy_path):
    """Remove a customer managed policy from a permission set"""
    logger.info(f'Removing Customer Managed Policy {policy_name} at {policy_path} for Permission Set: {local_name}')
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
        sleep(0.1)  # Avoid hitting API limit.
    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning("%s.Hit API limits. Sleep 2s...", error)
        sleep(2)
    except ic_admin.exceptions.ConflictException as error:
        logger.info("%s.The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
    except ClientError as error:
        error_message=f'Client error occurred: {error}'
        # logger.error(error_message)
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

    logger.info(f'Syncing AWS Managed Policies for Permission Set: {local_name}')

    # Get all the managed policies attached to the permission set.
    try:
        list_managed_policies = ic_admin.list_managed_policies_in_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )
        sleep(0.1)  # Avoid hitting API limit.

        # Populate arrays for Managed Policy tracking.
        for aws_managed_policy in list_managed_policies['AttachedManagedPolicies']:
            aws_managed_attached_names.append(aws_managed_policy['Name'])
            aws_managed_attached_dict[aws_managed_policy['Name']
                                      ] = aws_managed_policy['Arn']

        for local_managed_policy in local_managed_policies:
            local_policy_names.append(local_managed_policy['Name'])
            local_policy_dict[local_managed_policy['Name']] = local_managed_policy['Arn']

        for policy_name in local_policy_names:
            if not policy_name in aws_managed_attached_names:
                add_managed_policy_to_perm_set(local_name, perm_set_arn, local_policy_dict[policy_name])

        for aws_policy in aws_managed_attached_names:
            if not aws_policy in local_policy_names:
                remove_managed_policy_from_perm_set(local_name, perm_set_arn,
                                                    aws_managed_attached_dict[aws_policy])
    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning("%s.Hit IAM Identity Center API limits. Sleep 5s.", error)
        sleep(5)
    except ic_admin.exceptions.ConflictException as error:
        logger.warning("%s.The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
        sleep(2)
    except Exception as error:
        error_message=f'Exception occurred: {error}'
        # logger.error(error_message)
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

    logger.info(f'Syncing Customer Managed Policies for Permission Set: {local_name}')

    # Get all the customer managed policies attached to the permission set.
    try:
        list_cx_managed_policies = ic_admin.list_customer_managed_policy_references_in_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )
        sleep(0.1)  # Avoid hitting API limit.

        # Populate arrays for Customer Managed Policy tracking.
        for cx_managed_policy in list_cx_managed_policies['CustomerManagedPolicyReferences']:
            customer_managed_attached_names.append(cx_managed_policy['Name'])
            customer_managed_attached_dict[cx_managed_policy['Name']
                                           ] = cx_managed_policy['Path']

        for local_managed_policy in local_customer_policies:
            local_policy_names.append(local_managed_policy['Name'])
            local_policy_dict[local_managed_policy['Name']
                              ] = local_managed_policy['Path']

        # Iterate local policy dictionary(key and value):
        for policy_name, policy_path in local_policy_dict.items():
            if not policy_name in customer_managed_attached_names:
                add_cx_managed_policy_to_perm_set(local_name, perm_set_arn, policy_name,
                                                  policy_path)

        for ex_policy_name, ex_policy_path in customer_managed_attached_dict.items():
            if not ex_policy_name in local_policy_names:
                remove_cx_managed_policy_from_perm_set(local_name, perm_set_arn, ex_policy_name,
                                                       ex_policy_path)
    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning(
            "%s.Hit IAM Identity Center API limits. Sleep 5s.", error)
        sleep(5)
    except ic_admin.exceptions.ConflictException as error:
        logger.warning("%s.The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
        sleep(2)
    except Exception as error:
        error_message=f'Exception occurred: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)

def remove_inline_policies(local_name, perm_set_arn):
    """Remove Inline policies from permission set if they exist"""
    logger.info(f"Removing inline policies from permission set: {local_name} - {perm_set_arn}")
    try:
        list_existing_inline = ic_admin.get_inline_policy_for_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )

        if list_existing_inline['InlinePolicy']:
            ic_admin.delete_inline_policy_from_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn
            )
            logger.info('Removed inline policy for %s - %s', local_name, perm_set_arn)
            sleep(0.1)  # Avoid hitting API limit.
    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning(
            "%s.Hit IAM Identity Center API limit. Sleep 5s..", error)
        sleep(5)
    except ic_admin.exceptions.ConflictException as error:
        logger.warning("%s.The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
        sleep(2)
    except ClientError as error:
        error_message=f'Client error occurred: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)

def sync_inline_policies(local_name, local_inline_policy, perm_set_arn):
    """Synchronize Inline Policies as define in the JSON file with AWS"""
    logger.info(f"Syncing inline policies for permission set: {local_name} - {perm_set_arn}")
    if local_inline_policy:
        try:
            logger.info('Synchronizing inline policy with %s - %s', local_name, perm_set_arn)
            ic_admin.put_inline_policy_to_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                InlinePolicy=json.dumps(local_inline_policy)
            )
            sleep(0.1)  # Avoid hitting API limit.
        except ic_admin.exceptions.ThrottlingException as error:
            logger.warning("%s.Hit IAM Identity Center API limit. Sleep 5s...", error)
            sleep(5)
        except ic_admin.exceptions.ConflictException as error:
            logger.warning("%s.The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
        except ClientError as error:
            logger.warning("%s", error)
            # pipeline.put_job_failure_result(
            #     jobId=pipeline_id,
            #     failureDetails={'message': str(error), 'type': 'JobFailed'}
            # )
    else:
        remove_inline_policies(local_name, perm_set_arn)


def delete_permission_set(perm_set_arn, perm_set_name):
    """Delete IAM Identity Center permission sets"""
    logger.info(f"Deleting permission set: {perm_set_name} ({perm_set_arn})")
    try:
        ic_admin.delete_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )
        logger.info('%s Permission set deleted', perm_set_name)
        sleep(0.1)  # Avoid hitting API limit.
    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning("%s.Hit delete_permission_set API limits. Sleep 5s..", error)
        sleep(5)
    except ic_admin.exceptions.ConflictException as error:
        logger.warning("%sThe same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
    except ClientError as error:
        error_message=f'Client error occurred: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)

def put_permissions_boundary(local_name, perm_set_arn, boundary_policy):
    """Attach a permissions boundary to a permission set"""
    logger.info(f'Putting Permissions Boundary for Permission Set: {local_name} - {perm_set_arn}')
    try:
        if 'Path' in boundary_policy:
            # Customer managed policy
            ic_admin.put_permissions_boundary_to_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                PermissionsBoundaryType='CUSTOMER_MANAGED_POLICY',
                CustomerManagedPolicyReference={
                    'Name': boundary_policy['Name'],
                    'Path': boundary_policy['Path']
                }
            )
            sleep(0.1)
        else:
            # AWS managed policy
            ic_admin.put_permissions_boundary_to_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                PermissionsBoundaryType='MANAGED_POLICY',
                ManagedPolicyArn=boundary_policy['Arn']
            )
            sleep(0.1)
    except ClientError as error:
        error_message = f'Error attaching permission boundary for Permission Set {local_name} - {perm_set_arn}: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)

def delete_permissions_boundary(local_name, perm_set_arn):
    """Remove permissions boundary from a permission set"""
    logger.info(f'Deleting Permissions Boundary for Permission Set: {local_name} - {perm_set_arn}')
    try:
        ic_admin.delete_permissions_boundary_from_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )
        sleep(0.1)
    except ClientError as error:
        error_message = f'Error removing permission boundary from Permission Set {local_name} - {perm_set_arn}: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)
        
def sync_permissions_boundary(local_name, local_boundary, perm_set_arn):
    """Sync permissions boundary configuration"""
    logger.info(f'Syncing Permissions Boundary for Permission Set: {local_name} - {perm_set_arn}')
    try:
        current_boundary = None
        current_type = None
        try:
            boundary_info = ic_admin.describe_permissions_boundary_for_permission_set(
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
            # Determine if boundary configuration has changed
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
                put_permissions_boundary(local_name, perm_set_arn, local_boundary)
        elif current_boundary:
            delete_permissions_boundary(local_name, perm_set_arn)
            
    except ClientError as error:
        error_message = f'Error syncing permission boundary: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)

def sync_description(local_name, perm_set_arn, local_desc, aws_desc, session_duration):
    """Synchronize the description between the JSON file and AWS service"""
    logger.info(f'Syncing description for Permission Set: {local_name} - {perm_set_arn}')
    if not local_desc == aws_desc:
        try:
            logger.info('Updating description for %s - %s', local_name, perm_set_arn)
            ic_admin.update_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                SessionDuration=session_duration,
                Description=local_desc
            )
            sleep(0.1)  # Avoid hitting API limit.
        except ClientError as error:
            logger.warning("%s", error)


def tag_permission_set(local_name, local_tags, perm_set_arn):
    """Add tags to the permission sets"""
    try:
        ic_admin.tag_resource(
            InstanceArn=ic_instance_arn,
            ResourceArn=perm_set_arn,
            Tags=local_tags
        )
        logger.info('Tags added to or updated for %s - %s', local_name, perm_set_arn)
    except ClientError as error:
        error_message=f'Client error occurred: {error}'
        # logger.error(error_message)
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
        error_message=f'Client error occurred: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)

def sync_tags(local_name, local_tags, perm_set_arn):
    """Synchronize the tags between the JSON and AWS"""
    logger.info(f'Syncing tags for Permission Set: {local_name} - {perm_set_arn}')
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

    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning("%s.Hit ListTags API limits. Sleep 3s...", error)
        sleep(3)
    except ClientError as error:
        error_message=f'Client error occurred: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)

def get_accounts_by_perm_set(perm_set_arn):
    """List all the accounts for a given permission set"""
    try:
        response = ic_admin.list_accounts_for_provisioned_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )
        acct_list = response['AccountIds']
        while 'NextToken' in response:
            response = ic_admin.list_accounts_for_provisioned_permission_set(
                NextToken=response['NextToken'],
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn
            )
            acct_list += response['AccountIds']
        logger.debug(acct_list)
    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning("%s.Hit ListAccountsForProvisionedPermissionSet \
                        API limits. Sleep 5s.", error)
        sleep(5)
    except ClientError as error:
        error_message=f'Client error occurred: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)
    return acct_list


def deprovision_permission_set_from_accounts(perm_set_arn,
                                             perm_set_name):
    """
    Once the permission set is deleted. Automation will also
    remove any provisioned account assignments for this permission set.
    """
    try:
        account_ids = get_accounts_by_perm_set(perm_set_arn)

        # If the list of accounts is not null - remove all of the assignments
        if account_ids:
            for account in account_ids:
                # Get all of the assignments of a permission set
                response = ic_admin.list_account_assignments(
                    InstanceArn=ic_instance_arn,
                    AccountId=account,
                    PermissionSetArn=perm_set_arn
                )
                acct_assignments = response['AccountAssignments']
                while 'NextToken' in response:
                    ic_admin.list_account_assignments(
                        InstanceArn=ic_instance_arn,
                        AccountId=account,
                        PermissionSetArn=perm_set_arn,
                        NextToken=response['NextToken']
                    )
                    acct_assignments += response['AccountAssignments']

                # Remove all of the identified assignments for permission set
                for assignment in acct_assignments:
                    logger.info("Deleting assignment for account: %s, principal-type: %s, \
                                 principal-id: %s", account, assignment['PrincipalType'], assignment['PrincipalId'])
                    delete_assignment = ic_admin.delete_account_assignment(
                        InstanceArn=ic_instance_arn,
                        TargetId=account,
                        TargetType='AWS_ACCOUNT',
                        PermissionSetArn=perm_set_arn,
                        PrincipalType=assignment['PrincipalType'],
                        PrincipalId=assignment['PrincipalId']
                    )
                    logger.debug("%s", delete_assignment)
                    # Allow time for the deprovision - this should be refactored to be event driven
                    sleep(1)
        else:
            logger.info(
                '%s is not provisioned to any accounts - deleting...', perm_set_name)
    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning("%s.Hit API limits. Sleep 5s...", error)
        sleep(5)
    except ic_admin.exceptions.ConflictException as error:
        logger.warning("%sThe same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
        sleep(2)
    except ClientError as error:
        error_message=f'Client error occurred: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)

def reprovision_permission_sets(perm_set_name, perm_set_arn):
    """Find and re-provision the drifted permission sets"""

    logger.info(f'Reprovisioning Permission Set: {perm_set_name}')
    
    account_ids = get_accounts_by_perm_set(perm_set_arn)
    outdated_accounts = []

    # Look through the accounts to see if the permission set is
    #   not current and populate an array if any outdated one is found.
    for account in account_ids:
        try:
            outdated_perm_sets = ic_admin.list_permission_sets_provisioned_to_account(
                InstanceArn=ic_instance_arn,
                AccountId=account,
                ProvisioningStatus='LATEST_PERMISSION_SET_NOT_PROVISIONED'
            )
            sleep(0.1)  # Avoid hitting API limit.
            if outdated_perm_sets['PermissionSets']:
                outdated_accounts.append(outdated_perm_sets['PermissionSets'])
        except ic_admin.exceptions.ThrottlingException as error:
            logger.warning("%s.Hit API limits. Sleep 5s...", error)
            sleep(5)
        except ic_admin.exceptions.ConflictException as error:
            logger.warning("%sThe same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
            sleep(2)
        except ClientError as error:
            error_message=f'Client error occurred: {error}'
            # logger.error(error_message)
            log_and_append_error(error_message)

    # If any accounts were found to be out of date - reprovision the permission set to all accounts.
    # This can be done on an account by account level, but we'd have to monitor the status of every provision.
    if outdated_accounts:
        try:
            logger.info("Reprovisioning %s for the following \
                        accounts: %s", perm_set_name, account_ids)
            ic_admin.provision_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                TargetType='ALL_PROVISIONED_ACCOUNTS'
            )
            sleep(0.1)  # Avoid hitting API limit.

            # Find any IN_PROGRESS provisioning operations.
            get_provisionsing_status = ic_admin.list_permission_set_provisioning_status(
                InstanceArn=ic_instance_arn,
                Filter={
                    'Status': 'IN_PROGRESS'
                }
            )
            # Monitor the provisioning operation until it is no longer IN_PROGRESS.
            complete = 'false'
            for status in get_provisionsing_status['PermissionSetsProvisioningStatus']:
                while complete == 'false':
                    provision_status = ic_admin.describe_permission_set_provisioning_status(
                        InstanceArn=ic_instance_arn,
                        ProvisionPermissionSetRequestId=status['RequestId']
                    )
                    if provision_status['PermissionSetProvisioningStatus']['Status'] == 'IN_PROGRESS':
                        logger.info('Provisioning in progress...')
                        sleep(2)
                    else:
                        complete = 'true'
                        logger.info("Reprovisioning %s for the following \
                        accounts: %s completed successfully", perm_set_name, account_ids)
        except ic_admin.exceptions.ThrottlingException as error:
            logger.warning("%sHit API limits. Sleep 5s...", error)
            sleep(5)
        except ic_admin.exceptions.ConflictException as error:
            logger.warning("The same IAM Identity Center process may have been started in another invocation, or check for potential conflicts; skipping...", error)
            sleep(2)
        except ClientError as error:
            error_message=f'Client error occurred: {error}'
            # logger.error(error_message)
            log_and_append_error(error_message)

def validate_permission_set_schema(permission_set):
    """
    Validate the permission set schema.
    """
    required_keys = {
        "Name": str,
        "ManagedPolicies": list,
        "InlinePolicies": (list, dict)
    }

    optional_keys = {
        "Description": str,
        "Tags": list,
        "CustomerPolicies": list,
        "Session_Duration": str,
        "PermissionsBoundary": dict
    }

    # Validate PermissionsBoundary if present
    if 'PermissionsBoundary' in permission_set:
        boundary = permission_set['PermissionsBoundary']
        if not isinstance(boundary, dict) or 'Name' not in boundary or 'Arn' not in boundary:
            raise ValueError(f"PermissionsBoundary must be a dictionary with 'Name' and 'Arn' fields in permission set {permission_set_name}")

    permission_set_name = permission_set.get('Name', 'Unknown')

    # Validate required keys
    for key, expected_type in required_keys.items():
        if key not in permission_set:
            raise ValueError(f"Missing required key: {key} in permission set {permission_set_name}")
        if not isinstance(permission_set[key], expected_type):
            raise TypeError(f"Key '{key}' is not of expected type {expected_type.__name__} in permission set {permission_set_name}")

    # Validate optional keys if they are present
    for key, expected_type in optional_keys.items():
        if key in permission_set and not isinstance(permission_set[key], expected_type):
            raise TypeError(f"Optional key '{key}' is not of expected type {expected_type.__name__} in permission set {permission_set_name}")

    # Additional checks for 'Tags'
    if 'Tags' in permission_set:
        for tag in permission_set["Tags"]:
            if not isinstance(tag, dict) or "Key" not in tag or "Value" not in tag:
                raise ValueError(f"Each tag must be a dictionary with 'Key' and 'Value' fields in permission set {permission_set_name}")

    # Additional checks for 'ManagedPolicies'
    for policy in permission_set["ManagedPolicies"]:
        if not isinstance(policy, dict) or "Name" not in policy or "Arn" not in policy:
            raise ValueError(f"Each managed policy must be a dictionary with 'Name' and 'Arn' fields in permission set {permission_set_name}")

    # Additional checks for 'InlinePolicies' if it is a list or dict
    inline_policies = permission_set["InlinePolicies"]
    if isinstance(inline_policies, list):
        if inline_policies:  # If the list is not empty, raise an error
            raise ValueError(f"InlinePolicies list must be empty [] in permission set {permission_set_name}")
    elif isinstance(inline_policies, dict):
        if not ("Version" in inline_policies and "Statement" in inline_policies):
            raise ValueError(f"InlinePolicies dictionary must contain 'Version' and 'Statement' keys in permission set {permission_set_name}")
    else:
        raise TypeError(f"InlinePolicies must be either a list or a dictionary in permission set {permission_set_name}")



def sync_json_with_aws(local_files, aws_permission_sets):
    """Synchronize the repository's json files with the AWS Permission Sets"""
    local_permission_set_names = []
    local_customer_policies = []
    try:
        logger.info("Syncing permission sets into Identity Center")
        for local_file in local_files:
            local_session_duration = default_session_duration
            local_permission_set = local_files[local_file]
            try:
                validate_permission_set_schema(local_permission_set)
            except (ValueError, TypeError) as e:
                error_message=f'Validation error: {e}'
                # logger.error(error_message)
                log_and_append_error(error_message)
                return
            logger.info("Syncing %s", local_permission_set['Name'])
            local_name = local_permission_set['Name']
            local_desc = local_permission_set.get('Description', '-')
            local_tags = local_permission_set.get('Tags', [])
            local_managed_policies = local_permission_set['ManagedPolicies']
            local_inline_policy = local_permission_set['InlinePolicies']
            local_permission_set_names.append(local_name)

            # Customer managed policy is optional
            if "CustomerPolicies" in local_permission_set.keys():
                local_customer_policies = local_permission_set['CustomerPolicies']
            # Session Duration is optional
            if "Session_Duration" in local_permission_set.keys():
                local_session_duration = local_permission_set["Session_Duration"]

            # If Permission Set does not exist in AWS - add it.
            if local_name in aws_permission_sets:
                logger.info(
                    '%s exists in IAM Identity Center - checking policy and configuration', local_name)
            else:
                # Check if permission set exists in skipped list
                skipped = False
                for perm_set_arn, perm_set_name in skipped_perm_set.items():
                    if local_name == perm_set_name:
                        skipped = True
                        logger.warning(
                            'WARNING: Permission set %s already exists and is either managed by Control Tower, or provisioned in the management account. \
                            Please create a different permission set that will not be provisioned in the management account or not managed by Control Tower.', local_name)
                        break
                
                if not skipped:
                    logger.info(
                        'ADD OPERATION: %s does not exist in IAM Identity Center - adding...', local_name)
                    created_perm_set = create_permission_set(
                        local_name, local_desc, local_tags, local_session_duration)
                    created_perm_set_name = created_perm_set['PermissionSet']['Name']
                    created_perm_set_arn = created_perm_set['PermissionSet']['PermissionSetArn']
                    created_perm_set_desc = created_perm_set['PermissionSet']['Description']
                    aws_permission_sets[created_perm_set_name] = {
                        'Arn': created_perm_set_arn,
                        'Description': created_perm_set_desc
                    }

            # Check if permission set exists in skipped list
            skipped = False
            for perm_set_arn, perm_set_name in skipped_perm_set.items():
                if local_name == perm_set_name:
                    skipped = True
                    logger.warning(
                        'WARNING: Permission set %s already exists and is either managed by Control Tower, or provisioned in the management account. \
                        This Permission Set will not be synced', local_name)
                    break
            if not skipped:
                # Synchronize managed and inline policies for all local permission sets with AWS.
                sync_managed_policies(
                    local_name, local_managed_policies, aws_permission_sets[local_name]['Arn'])
                sync_customer_policies(
                    local_name, local_customer_policies, aws_permission_sets[local_name]['Arn'])
                sync_inline_policies(
                    local_name, local_inline_policy, aws_permission_sets[local_name]['Arn'])
                sync_description(local_name, aws_permission_sets[local_name]['Arn'], local_desc,
                                 aws_permission_sets[local_name]['Description'], local_session_duration)
                sync_tags(local_name, local_tags,
                          aws_permission_sets[local_name]['Arn'])
                
                # Sync permission boundary if configured
                local_boundary = local_permission_set.get('PermissionsBoundary')
                sync_permissions_boundary(local_name, local_boundary, aws_permission_sets[local_name]['Arn'])
                
                reprovision_permission_sets(
                        local_name, aws_permission_sets[local_name]['Arn'])

        # If a permission set exists in AWS but not on the local - delete it
        for aws_perm_set in aws_permission_sets:
            if not aws_perm_set in local_permission_set_names:
                try:
                    skipped = False
                    for perm_set_arn, perm_set_name in skipped_perm_set.items():
                        if aws_perm_set == perm_set_name:
                            skipped = True
                            logger.warning(
                                'WARNING: Permission set %s already exists and is either managed by Control Tower, or provisioned in the management account. \
                                Please create a different permission set that will not be provisioned in the management account or not managed by Control Tower.', aws_perm_set)
                            break
                    if not skipped:
                        logger.info(
                            'DELETE OPERATION: %s does not exist locally - deleting...', aws_perm_set)
                        deprovision_permission_set_from_accounts(
                                aws_permission_sets[aws_perm_set]['Arn'], aws_perm_set)
                        delete_permission_set(
                            aws_permission_sets[aws_perm_set]['Arn'], aws_perm_set)
                except Exception as error:
                    error_message=f'Delete failed due to: {error}'
                    # logger.error(error_message)
                    log_and_append_error(error_message)
    except Exception as error:
        error_message=f'Sync AWS permission sets failed. Error: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)
        if errors:
            error_message = f'Errors encountered during processing: {errors}'
        sys.exit(1)
        # quit()
    return "Synchronized AWS Permission Sets with new updated definition."

def start_automation():
    try:
        logger.info("The automation process is now started.")
        if delegated == "true":
            aws_permission_sets = get_all_permission_sets_if_delegate()
            logger.info("The existing aws_permission_sets are : %s",
                    aws_permission_sets)
        else:
            aws_permission_sets = get_all_permission_sets()
            logger.info("The existing aws_permission_sets are : %s",
                    aws_permission_sets)
        # Get the permission set's baseline by loading S3 bucket files
        json_files = get_all_json_files(ic_bucket_name)
        sync_json_with_aws(json_files, aws_permission_sets)
        # Next function auto-assignment will be executed after this function ends
        logger.info("Execution completed! \
                    Check the auto assignment function logs for further execution details.")
        # accountid = build_arn.split(':')[4]
        # invoke_auto_assignment()
    except Exception as error:
        error_message=f'Exception occurred: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)

def main(event=None):
    """
    Main function to handle Pipeline triggered and EventBridge triggered events for permission set automation.

    Args:
        event (dict, optional): Event payload if triggered by EventBridge Rules.
        Defaults to None.
    """

    global errors
    errors = []
    
    # logger.debug(context)
    logger.info('Boto3 version: %s', boto3.__version__)
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
            logger.info(f"This build is triggered by {build_initiator} either manually or by an unknown source")
            
        start_automation()
        if errors:
            logger.error(f'All Errors during execution: {errors}')
            logger.info("Execution is complete.")
            sys.exit(1) # Signal failure to CodeBuild
        else:
            logger.info("Execution is complete.")

    except Exception as error:
        error_message = f'Exception occurred: {error}'
        # logger.error(error_message)
        log_and_append_error(error_message)
        if errors:
            logger.error(f'Errors during execution: {errors}')
            sys.exit(1) # Signal failure to CodeBuild

if __name__ == "__main__":
    logger.info(f'Codebuild logs contain combined logs for the build project.\
                If you wish to view the logs for auto-permissionSet function, you can check out CloudWatch logs: "{permission_set_automation_log_group}/[buildId]-{build_id}"\
                    https://{runtime_region}.console.aws.amazon.com/cloudwatch/home?region={runtime_region}#logsV2:log-groups/log-group/{permission_set_automation_log_group}/log-events/[buildId]-{build_id}')
    main(event)
    # Flush and close watchtower
    watchtower_handler.flush()
    watchtower_handler.close()