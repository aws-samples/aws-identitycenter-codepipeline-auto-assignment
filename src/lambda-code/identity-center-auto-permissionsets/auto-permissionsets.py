"""Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved"""
# pylint: disable=C0301
# pylint: disable=W1202,W0703
# pylint: disable=E0401

####################################################################
# A workaround of upgrade the boto3 version in the lambda function #
####################################################################
import cfnresponse
from time import sleep
import json
import os
import logging
import sys
from pip._internal import main
main(['install', '-I', '-q', 'boto3', '--target', '/tmp/',
     '--no-cache-dir', '--disable-pip-version-check'])
sys.path.insert(0, '/tmp/')
import boto3
from botocore.exceptions import ClientError


logger = logging.getLogger()
logger.setLevel(logging.INFO)

logger.info("Logging initialized")


runtime_region = os.environ['Lambda_Region']
ic_bucket_name = os.environ.get('IC_S3_BucketName')
pipeline = boto3.client('codepipeline', region_name=runtime_region)
s3 = boto3.resource('s3')
sns_client = boto3.client('sns', region_name=runtime_region)
sns_topic_name = os.environ.get('SNS_Topic_Name')
ic_admin = boto3.client('sso-admin', region_name=runtime_region)
ic_instance_arn = os.environ.get('IC_InstanceArn')
default_session_duration = os.environ.get('Session_Duration')
management_account_id = os.environ.get('Org_Management_Account')
delegated = os.environ.get('AdminDelegated')
dynamodb = boto3.client('dynamodb', region_name=runtime_region)

def sync_table_for_skipped_perm_sets(skipped_perm_set):
    """Sync DynamoDB table with the list of skipped permission sets if Admin is delegated"""
    try:
        response = dynamodb.scan(
            TableName='ic-SkippedPermissionSetsTable')
        items = response['Items']
        print(f"Items in DynamoDB table: {items}")
        for item in items:
            # If the permission set is not in the current skipped_perm_set, delete it from the table
            if item['perm_set_arn']['S'] not in skipped_perm_set:
                dynamodb.delete_item(
                    TableName='ic-SkippedPermissionSetsTable',
                    Key={'perm_set_arn': item['perm_set_arn']}
                )
                print(f"Drift detected in DynamoDB table. Deleted item: {item} from table.")

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
            logger.error("There were unprocessed skipped permission sets while writing to DynamoDB table: %s" % unprocessed_items)
        else:
            logger.info("All skipped permission sets written successfully to the table")
    except Exception as error:
        logger.error("Error syncing with DynamoDB table: %s", error)

def get_all_permission_sets(pipeline_id):
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
        skipped_perm_set = {}
        for perm_set_arn in all_perm_sets_arns:
            describe_perm_set = ic_admin.describe_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn
            )
            sleep(0.1)  # Aviod hitting API limit.
            description = ''
            try:
                description = describe_perm_set['PermissionSet']['Description']
            except Exception as error:
                logger.error(
                    "Failed to get description for permission set %s. Error: %s", perm_set_arn, error)
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
        logger.info("The same IAM Identity Center process has been started \
                    in another invocation, skipping...%s", error)
        sleep(2)
    except ClientError as error:
        logger.error("%s", error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'message':str(error), 'type': 'JobFailed'}
        )
    if skipped_perm_set:
        try:
            print(f"Skipped Permission Set Name and ARN: {skipped_perm_set}")
            sync_table_for_skipped_perm_sets(skipped_perm_set)
        except Exception as error:
            logger.error(
                "Failed to invoke sync_table_for_skipped_perm_sets %s", error)
    else:
        print("No Permission Sets were skipped")
    return permission_set_name_and_arn

def get_all_permission_sets_if_delegate(pipeline_id):
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

        skipped_perm_set = {}
        for perm_set_arn in all_perm_sets_arns:
            describe_perm_set = ic_admin.describe_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn
            )
            sleep(0.1)  # Aviod hitting API limit.
            description = ''
            try:
                description = describe_perm_set['PermissionSet']['Description']
            except Exception as error:
                logger.error("Failed to get description for permission set %s. Error: %s", perm_set_arn, error)
            perm_set_name = describe_perm_set['PermissionSet']['Name']
            perm_set_arn = describe_perm_set['PermissionSet']['PermissionSetArn']
            list_accounts_for_provisioned_perm_set = ic_admin.list_accounts_for_provisioned_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                MaxResults=100,
            )
            accounts_for_perm_set = list_accounts_for_provisioned_perm_set['AccountIds']
            sleep(0.1)  # Aviod hitting API limit.
            while 'NextToken' in list_accounts_for_provisioned_perm_set:
                list_accounts_for_provisioned_perm_set = ic_admin.list_accounts_for_provisioned_permission_set(
                    InstanceArn=ic_instance_arn,
                    PermissionSetArn=perm_set_arn,
                    MaxResults=100,
                    NextToken=list_accounts_for_provisioned_perm_set['NextToken']
                )
                sleep(0.1)  # Aviod hitting API limit.
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
        logger.info("The same IAM Identity Center process has been started \
                    in another invocation, skipping...%s", error)
        sleep(2)
    except ClientError as error:
        logger.error("%s", error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'message':str(error), 'type': 'JobFailed'}
        )
    if skipped_perm_set:
        try:
            print(f"Skipped Permission Set Name and ARN: {skipped_perm_set}")
            sync_table_for_skipped_perm_sets(skipped_perm_set)
        except Exception as error:
            logger.error(
                "Failed to invoke sync_table_for_skipped_perm_sets %s", error)
    else:
        print("No Permission Sets were skipped")
    return permission_set_name_and_arn


def get_all_json_files(bucket_name, pipeline_id):
    """Download all the JSON files from IAM Identity Center S3 bucket"""
    logger.info("Getting all json files from S3 bucket")
    file_contents = {}
    my_bucket = s3.Bucket(bucket_name)
    try:
        for s3_object in my_bucket.objects.filter(Prefix="permission-sets/"):
            if ".json" in s3_object.key:
                file_name = s3_object.key
                logger.info("processing file: %s", file_name)
                s3.Bucket(bucket_name).download_file(
                    file_name, "/tmp/each_permission_set.json")
                temp_file = open("/tmp/each_permission_set.json")
                data = json.load(temp_file)
                file_contents[file_name] = data
                logger.debug("File data: %s", data)
                temp_file.close()
    except Exception as error:
        logger.error("Cannot load permission set \
                     content from s3 file %s ", error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'message': str(error), 'type': 'JobFailed'}
        )
    return file_contents


def create_permission_set(name, desc, tags, session_duration, pipeline_id):
    """Create a permission set in AWS IAM Identity Center"""
    try:
        response = ic_admin.create_permission_set(
            Name=name,
            Description=desc,
            InstanceArn=ic_instance_arn,
            SessionDuration=session_duration,
            Tags=tags
        )
        sleep(0.1)  # Aviod hitting API limit.
    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning(
            "%sHit CreatePermissionSet API limits. Sleep 5s.", error)
        sleep(5)
    except ic_admin.exceptions.ConflictException as error:
        logger.info("%sThe same IAM Identity Center process has been \
                    started in another invocation, skipping...", error)
        sleep(2)
    except ClientError as error:
        logger.error("%s", error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'message': str(error), 'type': 'JobFailed'}
        )
    return response


def add_managed_policy_to_perm_set(perm_set_arn, managed_policy_arn,
                                   pipeline_id):
    """Attach a managed policy to a permission set"""
    try:
        attach_managed_policy = ic_admin.attach_managed_policy_to_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn,
            ManagedPolicyArn=managed_policy_arn
        )
        logger.info('Managed Policy %s added to %s',
                    managed_policy_arn, perm_set_arn)
        sleep(0.1)  # Aviod hitting API limit.

    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning("%s.Hit API limits. Sleep 2s.", error)
        sleep(2)
    except ic_admin.exceptions.ConflictException as error:
        logger.info("%s.The same IAM Identity Center process has been started in \
                    another invocation, skipping...", error)
    except ClientError as error:
        logger.error("%s", error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'message': str(error), 'type': 'JobFailed'}
        )
    return attach_managed_policy


def remove_managed_policy_from_perm_set(perm_set_arn, managed_policy_arn, pipeline_id):
    """Remove a managed policy from a permission set"""
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
        logger.info(
            "%s.The same IAM Identity Center process has been started in another invocation, skipping...", error)
    except ClientError as error:
        logger.error("%s", error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'message': str(error), 'type': 'JobFailed'}
        )
    return remove_managed_policy


def add_cx_managed_policy_to_perm_set(perm_set_arn, policy_name,
                                      policy_path, pipeline_id):
    """Attach a customer managed policy to a permission set"""
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
                    perm_set_arn)
        sleep(0.1)  # Aviod hitting API limit.

    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning("%s.Hit API limits. Sleep 2s.", error)
        sleep(2)
    except ic_admin.exceptions.ConflictException as error:
        logger.info("%s.The same IAM Identity Center process has been started in \
                    another invocation, skipping...", error)
    except ClientError as error:
        logger.error("%s", error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'message': str(error), 'type': 'JobFailed'}
        )
    return attach_cx_managed_policy


def remove_cx_managed_policy_from_perm_set(perm_set_arn, policy_name, policy_path,
                                           pipeline_id):
    """Remove a customer managed policy from a permission set"""
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
                    from %s', policy_name, perm_set_arn)
        sleep(0.1)  # Avoid hitting API limit.
    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning("%s.Hit API limits. Sleep 2s...", error)
        sleep(2)
    except ic_admin.exceptions.ConflictException as error:
        logger.info(
            "%s.The same IAM Identity Center process has been started in another invocation, skipping...", error)
    except ClientError as error:
        logger.error("%s", error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'message': str(error), 'type': 'JobFailed'}
        )
    return remove_cx_managed_policy


def sync_managed_policies(local_managed_policies, perm_set_arn, pipeline_id):
    """
    Synchronize Managed Polcieis as defined in the JSON file with AWS
    Declare arrays for keeping track on Managed policies locally and on AWS
    """
    aws_managed_attached_names = []
    aws_managed_attached_dict = {}
    local_policy_names = []
    local_policy_dict = {}

    # Get all the managed polcies attached to the permission set.
    try:
        list_managed_policies = ic_admin.list_managed_policies_in_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )
        sleep(0.1)  # Aviod hitting API limit.

        # Populate arrays for Managed Policy tracking.
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
                add_managed_policy_to_perm_set(perm_set_arn, local_policy_dict[policy_name],
                                               pipeline_id)

        for aws_policy in aws_managed_attached_names:
            if not aws_policy in local_policy_names:
                remove_managed_policy_from_perm_set(perm_set_arn,
                                                    aws_managed_attached_dict[aws_policy],
                                                    pipeline_id)
    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning(
            "%s.Hit IAM Identity Center API limits. Sleep 5s.", error)
        sleep(5)
    except ic_admin.exceptions.ConflictException as error:
        logger.info("%s.The same IAM Identity Center process has been started \
                    in another invocation, skipping...", error)
        sleep(2)
    except Exception as error:
        logger.error("%s", error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'message': str(error), 'type': 'JobFailed'}
        )


def sync_customer_policies(local_customer_policies, perm_set_arn, pipeline_id):
    """
    Synchronize customer managed polcies as defined in the JSON file with AWS
    Declare arrays for keeping track on custom policies locally and on AWS
    """
    customer_managed_attached_names = []
    customer_managed_attached_dict = {}
    local_policy_names = []
    local_policy_dict = {}

    # Get all the customer managed polcies attached to the permission set.
    try:
        list_cx_managed_policies = ic_admin.list_customer_managed_policy_references_in_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )
        sleep(0.1)  # Aviod hitting API limit.

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
                add_cx_managed_policy_to_perm_set(perm_set_arn, policy_name,
                                                  policy_path, pipeline_id)

        for ex_policy_name, ex_policy_path in customer_managed_attached_dict.items():
            if not ex_policy_name in local_policy_names:
                remove_cx_managed_policy_from_perm_set(perm_set_arn, ex_policy_name,
                                                       ex_policy_path, pipeline_id)
    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning(
            "%s.Hit IAM Identity Center API limits. Sleep 5s.", error)
        sleep(5)
    except ic_admin.exceptions.ConflictException as error:
        logger.info("%s.The same IAM Identity Center process has been started \
                    in another invocation, skipping...", error)
        sleep(2)
    except Exception as error:
        logger.error("%s", error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'message': str(error), 'type': 'JobFailed'}
        )


def remove_inline_policies(perm_set_arn, pipeline_id):
    """Remove Inline policies from permission set if they exist"""
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
            logger.info('Removed inline policiy for %s', perm_set_arn)
            sleep(0.1)  # Aviod hitting API limit.
    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning(
            "%s.Hit IAM Identity Center API limit. Sleep 5s..", error)
        sleep(5)
    except ic_admin.exceptions.ConflictException as error:
        logger.info("%s.The same IAM Identity Center process has been started \
                    in another invocation, skipping...", error)
        sleep(2)
    except ClientError as error:
        logger.error("%s", error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'message': str(error), 'type': 'JobFailed'}
        )


def sync_inline_policies(local_inline_policy, perm_set_arn, pipeline_id):
    """Synchronize Inline Policies as define in the JSON file with AWS"""
    if local_inline_policy:
        try:
            logger.info('Synchronizing inline policy with %s', perm_set_arn)
            ic_admin.put_inline_policy_to_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                InlinePolicy=json.dumps(local_inline_policy)
            )
            sleep(0.1)  # Aviod hitting API limit.
        except ic_admin.exceptions.ThrottlingException as error:
            logger.warning(
                "%s.Hit IAM Identity Center API limit. Sleep 5s...", error)
            sleep(5)
        except ic_admin.exceptions.ConflictException as error:
            logger.info("%s.The same IAM Identity Center process has been started \
                        in another invocation, skipping...", error)
        except ClientError as error:
            logger.warning("%s", error)
            pipeline.put_job_failure_result(
                jobId=pipeline_id,
                failureDetails={'message': str(error), 'type': 'JobFailed'}
            )
    else:
        remove_inline_policies(perm_set_arn, pipeline_id)


def delete_permission_set(perm_set_arn, perm_set_name, pipeline_id):
    """Delete IAM Identity Center permission sets"""
    try:
        ic_admin.delete_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )
        logger.info('%s Permission set deleted', perm_set_name)
        sleep(0.1)  # Aviod hitting API limit.
    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning(
            "%s.Hit delete_permission_set API limits. Sleep 5s..", error)
        sleep(5)
    except ic_admin.exceptions.ConflictException as error:
        logger.info("%s.The same IAM Identity Center process has been started \
                    in another invocation, skipping...", error)
    except ClientError as error:
        logger.error("%s", error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'message': str(error), 'type': 'JobFailed'}
        )


def sync_description(perm_set_arn, local_desc, aws_desc, session_duration):
    """Synchronize the description between the JSON file and AWS service"""
    if not local_desc == aws_desc:
        try:
            logger.info('Updating description for %s', perm_set_arn)
            ic_admin.update_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn,
                SessionDuration=session_duration,
                Description=local_desc
            )
            sleep(0.1)  # Aviod hitting API limit.
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
        logger.info('Tags added to or updated for %s', local_name)
    except ClientError as error:
        logger.error("%s", error)


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
        logger.info('Tag removed from %s', local_name)
    except ClientError as error:
        logger.error("%s.", error)


def sync_tags(local_name, local_tags, perm_set_arn):
    """Synchronize the tags between the JSON and AWS"""
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
        logger.error("%s", error)


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
        logger.error("%s", error)
    return acct_list


def deprovision_permission_set_from_accounts(perm_set_arn,
                                             perm_set_name, pipeline_id):
    """
    Once the permission set is deleted. Lambda function will also
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
        logger.info("%s.The same IAM Identity Center process has been started \
                    in another invocation, skipping...", error)
        sleep(2)
    except ClientError as error:
        logger.error("%s", error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'message': str(error), 'type': 'JobFailed'}
        )


def reprovision_permission_sets(perm_set_name, perm_set_arn, pipeline_id):
    """Find and re-provision the drifted permission sets"""
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
            sleep(0.1)  # Aviod hitting API limit.
            if outdated_perm_sets['PermissionSets']:
                outdated_accounts.append(outdated_perm_sets['PermissionSets'])
        except ic_admin.exceptions.ThrottlingException as error:
            logger.warning("%s.Hit API limits. Sleep 5s...", error)
            sleep(5)
        except ic_admin.exceptions.ConflictException as error:
            logger.info("%sThe same IAM Identity Center process has been started \
                        in another invocation, skipping...", error)
            sleep(2)
        except ClientError as error:
            logger.error("%s", error)
            pipeline.put_job_failure_result(
                jobId=pipeline_id,
                failureDetails={'message': str(error), 'type': 'JobFailed'}
            )

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
            sleep(0.1)  # Aviod hitting API limit.

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
        except ic_admin.exceptions.ThrottlingException as error:
            logger.warning("%sHit API limits. Sleep 5s...", error)
            sleep(5)
        except ic_admin.exceptions.ConflictException as error:
            logger.info("The same IAM Identity Center process has been started \
                        in another invocation, skipping...", error)
            sleep(2)
        except ClientError as error:
            logger.error("%s", error)
            pipeline.put_job_failure_result(
                jobId=pipeline_id,
                failureDetails={'message': str(error), 'type': 'JobFailed'}
            )

def sync_json_with_aws(local_files, aws_permission_sets, pipeline_id):
    """Synchronize the repository's json files with the AWS Permission Sets"""
    local_permission_set_names = []
    local_customer_policies = []
    try:
        for local_file in local_files:
            local_session_duration = default_session_duration
            local_permission_set = local_files[local_file]
            local_name = local_permission_set['Name']
            local_desc = local_permission_set['Description']
            local_tags = local_permission_set['Tags']
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
                logger.info(
                    'ADD OPERATION: %s does not exist in IAM Identity Center - adding...', local_name)
                created_perm_set = create_permission_set(
                    local_name, local_desc, local_tags, local_session_duration, pipeline_id)
                created_perm_set_name = created_perm_set['PermissionSet']['Name']
                created_perm_set_arn = created_perm_set['PermissionSet']['PermissionSetArn']
                created_perm_set_desc = created_perm_set['PermissionSet']['Description']
                aws_permission_sets[created_perm_set_name] = {
                    'Arn': created_perm_set_arn,
                    'Description': created_perm_set_desc
                }

            # Synchronize managed and inline policies for all local permission sets with AWS.
            sync_managed_policies(
                local_managed_policies, aws_permission_sets[local_name]['Arn'], pipeline_id)
            sync_customer_policies(
                local_customer_policies, aws_permission_sets[local_name]['Arn'], pipeline_id)
            sync_inline_policies(
                local_inline_policy, aws_permission_sets[local_name]['Arn'], pipeline_id)
            sync_description(aws_permission_sets[local_name]['Arn'], local_desc,
                             aws_permission_sets[local_name]['Description'], local_session_duration)
            sync_tags(local_name, local_tags,
                      aws_permission_sets[local_name]['Arn'])
            reprovision_permission_sets(
                    local_name, aws_permission_sets[local_name]['Arn'], pipeline_id)

        # If a permission set exists in AWS but not on the local - delete it
        for aws_perm_set in aws_permission_sets:
            if not aws_perm_set in local_permission_set_names:
                logger.info(
                    'DELETE OPERATION: %s does not exist locally - deleting...', aws_perm_set)
                deprovision_permission_set_from_accounts(
                        aws_permission_sets[aws_perm_set]['Arn'], aws_perm_set, pipeline_id)
                delete_permission_set(
                    aws_permission_sets[aws_perm_set]['Arn'], aws_perm_set, pipeline_id)
    except Exception as error:
        logger.error("Sync AWS permission sets failed due to %s", error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'message': str(error), 'type': 'JobFailed'}
        )
        quit()
    return "Synchronized AWS Permission Sets with new updated defination."


def invoke_auto_assignment(topic_name, accountid, pipeline_id):
    """Use SNS topic to invoke auto assignment Lambda function"""

    try:
        topic_arn = 'arn:aws:sns:'+runtime_region + \
            ':'+str(accountid)+':'+topic_name
        response = sns_client.publish(
            TopicArn=topic_arn,
            Message=pipeline_id
        )
        logger.info("%s", response)
    except Exception as error:
        if pipeline_id == 'AWS API Call via CloudTrail':
            logger.error("Error invoking auto-assignment: %s", error)
        elif pipeline_id != '':
            logger.error("%s", error)
            pipeline.put_job_failure_result(
                jobId=pipeline_id,
                failureDetails={'message': str(error), 'type': 'JobFailed'}
            )


def lambda_handler(event, context):
    """Lambda_handler"""
    logger.info(event)
    logger.debug(context)
    logger.info('Boto3 version: %s', boto3.__version__)

    pipeline_id = ""

    if 'RequestType' in event and event['RequestType'] == 'Delete':
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {})

    elif 'CodePipeline.job' in event:
        try:
            pipeline_id = event['CodePipeline.job']['id']
            logger.info("The automation process is now started. %s",
                        str(pipeline_id))
            if delegated == "true":
                aws_permission_sets = get_all_permission_sets_if_delegate(pipeline_id)
                logger.info("The existing aws_permission_sets are : %s",
                        aws_permission_sets)
            else:
                aws_permission_sets = get_all_permission_sets(pipeline_id)
                logger.info("The existing aws_permission_sets are : %s",
                        aws_permission_sets)
            # Get the permission set's baseline by loading S3 bucket files
            json_files = get_all_json_files(ic_bucket_name, pipeline_id)
            sync_json_with_aws(json_files, aws_permission_sets, pipeline_id)
            # Invoke Next automation lambda function
            logger.info("Published sns topic to invoke auto assignment function. \
                        Check the auto assignment lambda funcion log for further execution details.")
            accountid = context.invoked_function_arn.split(':')[4]
            invoke_auto_assignment(sns_topic_name, accountid, pipeline_id)

        except Exception as error:
            logger.error("%s", error)
            pipeline.put_job_failure_result(
                jobId=pipeline_id,
                failureDetails={'message': str(error), 'type': 'JobFailed'}
            )

    elif event['detail-type'] == 'AWS API Call via CloudTrail':
        sleep(10)
        event_detail_type = event['detail-type']
        try:
            print("The automation process is now started. This event is triggered by EventBridge")
            if delegated == "true":
                aws_permission_sets = get_all_permission_sets_if_delegate(pipeline_id)
                logger.info("The existing aws_permission_sets are : %s",
                        aws_permission_sets)
            else:
                aws_permission_sets = get_all_permission_sets(pipeline_id)
                logger.info("The existing aws_permission_sets are : %s",
                        aws_permission_sets)
            # Get the permission set's baseline by loading S3 bucket files
            json_files = get_all_json_files(ic_bucket_name, pipeline_id)
            sync_json_with_aws(json_files, aws_permission_sets, pipeline_id)
            # Invoke Next automation lambda function
            print("Published sns topic to invoke auto assignment function.")
            logger.info("Published sns topic to invoke auto assignment function. \
                        Check the auto assignment lambda funcion log for further execution details.")
            accountid = context.invoked_function_arn.split(':')[4]
            print(f"Account ID: {accountid}")
            print(f"SNS Topic Name: {sns_topic_name}")
            invoke_auto_assignment(sns_topic_name, accountid, event_detail_type)

        except Exception as error:
            logger.error("%s", error)
            pipeline.put_job_failure_result(
                jobId=pipeline_id,
                failureDetails={'message': str(error), 'type': 'JobFailed'}
            )
