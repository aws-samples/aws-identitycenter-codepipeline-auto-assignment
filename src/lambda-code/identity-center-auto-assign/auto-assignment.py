"""Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved"""
# pylint: disable=C0301
# pylint: disable=W1202,W0703
# pylint: disable=E0401
import os
import json
import logging
from time import sleep
import boto3
from botocore.exceptions import ClientError

runtime_region = os.environ['Lambda_Region']
global_mapping_file_name = os.environ.get('GlobalFileName')
identity_store_id = os.environ.get('IdentityStore_Id')
identitystore_client = boto3.client(
    'identitystore', region_name=runtime_region)
orgs_client = boto3.client('organizations', region_name=runtime_region)
pipeline = boto3.client('codepipeline', region_name=runtime_region)
s3client = boto3.client('s3', region_name=runtime_region)
ic_admin = boto3.client('sso-admin', region_name=runtime_region)
ic_bucket_name = os.environ.get('IC_S3_BucketName')
ic_instance_arn = os.environ.get('IC_InstanceArn')
target_mapping_file_name = os.environ.get('TargetFileName')
management_account_id = os.environ.get('Org_Management_Account')
delegated = os.environ.get('AdminDelegated')

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def list_all_current_account_assignment(acct_list, current_aws_permission_sets,
                                        pipeline_id):
    """List all the current account assignments information"""
    all_assignments = []
    for each_perm_set_name in current_aws_permission_sets:
        try:
            for account in acct_list:
                if account['Status'] != "SUSPENDED":
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
                            # After remove USER assignee, append all other GROUP assignee to the list.
                            else:
                                all_assignments.append(each_assignment)
        except ic_admin.exceptions.ThrottlingException as error:
            logger.warning(
                "%s. Hit IAM Identity Center API limit. Sleep 3s...", error)
            sleep(3)
        except Exception as error:
            logger.error("%s", error)
            pipeline.put_job_failure_result(
                jobId=pipeline_id,
                failureDetails={'type': 'JobFailed', 'message': str(error)}
            )
    logger.info("Current GROUP assignments: %s", all_assignments)
    return all_assignments

def drift_detect_update(all_assignments, global_file_contents,
                        target_file_contents, current_aws_permission_sets,
                        pipeline_id):
    """Use new mapping information to update IAM Identity Center assignments"""
    check_list = all_assignments
    remove_list = []
    for each_assignment in check_list:
        try:
            logger.debug("list each global assignment:%s", each_assignment)
            for global_mapping in global_file_contents:
                for each_perm_set_name in global_mapping['PermissionSetName']:
                    global_group_id = get_groupid(
                        global_mapping['GlobalGroupName'])
                    permission_set_arn = current_aws_permission_sets[each_perm_set_name]['Arn']
                    # Remove matched assignment from list:
                    if each_assignment['PrincipalId'] == global_group_id and each_assignment["PermissionSetArn"] == permission_set_arn:
                        remove_list.append(each_assignment)
        except ic_admin.exceptions.ThrottlingException as error:
            logger.warning(
                "%s. Hit IAM Identity Center API limit. Sleep 3s...", error)
            sleep(3)
        except Exception as error:
            logger.error("%s", error)
            pipeline.put_job_failure_result(
                jobId=pipeline_id,
                failureDetails={'type': 'JobFailed', 'message': str(error)}
            )
    for each_assignment in check_list:
        try:
            for target_mapping in target_file_contents:
                if each_assignment['AccountId'] in target_mapping['TargetAccountid']:
                    for each_perm_set_name in target_mapping['PermissionSetName']:
                        permission_set_arn = current_aws_permission_sets[each_perm_set_name]['Arn']
                        target_group_id = get_groupid(
                            target_mapping['TargetGroupName'])
                    if each_assignment['PrincipalId'] == target_group_id and each_assignment['PermissionSetArn'] == permission_set_arn:
                        remove_list.append(each_assignment)
        except ic_admin.exceptions.ThrottlingException as error:
            logger.warning(
                "%s. Hit IAM Identity Center API limit. Sleep 3s...", error)
            sleep(3)
        except Exception as error:
            logger.error("%s", error)
            pipeline.put_job_failure_result(
                jobId=pipeline_id,
                failureDetails={'type': 'JobFailed', 'message': str(error)}
            )
    for item in remove_list:
        check_list.remove(item)
    # Search drift by checking the element that remain in check_list.
    if len(check_list) == 0:
        logger.info(
            "IAM Identity Center assignments has been applied. No drift was found within current assignments :)")
    else:
        for delta_assignment in check_list:
            try:
                print(f"Assignment with drift: {delta_assignment}")
                delete_user_assignment = ic_admin.delete_account_assignment(
                    InstanceArn=ic_instance_arn,
                    TargetId=delta_assignment['AccountId'],
                    TargetType='AWS_ACCOUNT',
                    PermissionSetArn=delta_assignment['PermissionSetArn'],
                    PrincipalType='GROUP',
                    PrincipalId=delta_assignment['PrincipalId']
                )
                logger.warning(
                    "Warning. Drift has been detected and removing..%s", delete_user_assignment)
            except ic_admin.exceptions.ThrottlingException as error:
                logger.warning("%s. Hit API limits. Sleep 3s...", error)
                sleep(3)
            except Exception as error:
                logger.error("%s", error)
                pipeline.put_job_failure_result(
                    jobId=pipeline_id,
                    failureDetails={'type': 'JobFailed', 'message': str(error)}
                )


def get_global_mapping_contents(bucketname, global_mapping_file, pipeline_id):
    """Get global mapping info from JSON files"""
    try:
        filedata = s3client.get_object(
            Bucket=bucketname,
            Key=global_mapping_file
        )
        content = filedata['Body']
        json_object = json.loads(content.read())

    except Exception as error:
        logger.warning("Cannot get global mapping information.\
            Did you upload the global mapping file in correct JSON format? %s", error)
        # Exit to prevent from accidently wiping out all the attachment.
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'type': 'JobFailed', 'message': str(error)}
        )
        quit()
    return json_object


def get_target_mapping_contents(bucketname, target_mapping_file, pipeline_id):
    """Get target mapping info from uploaded JSON files"""
    try:
        filedata = s3client.get_object(
            Bucket=bucketname,
            Key=target_mapping_file
        )
        content = filedata['Body']
        json_object = json.loads(content.read())

    except Exception as error:
        logger.warning("Cannot get target mapping information.\
            Did you upload the target mapping file in correct JSON format? %s", error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'type': 'JobFailed', 'message': str(error)}
        )
        quit()
    return json_object

def validate_permission_set_file_structure(permission_set_file):
    """
    Validate the structure of the permission set file.
    """
    required_keys = {
        "GlobalGroupName": str,
        "PermissionSetName": list,
        "TargetAccountid": str
    }

    if not isinstance(permission_set_file, list):
        raise TypeError("The permission set file must be a list")

    for idx, permission_set in enumerate(permission_set_file):
        if not isinstance(permission_set, dict):
            raise TypeError(f"Each item in the permission set file must be a dictionary. Item at index {idx} is not a dictionary.")

        for key, expected_type in required_keys.items():
            if key not in permission_set:
                raise ValueError(f"Missing required key: {key} in permission set at index {idx}")
            if not isinstance(permission_set[key], expected_type):
                raise TypeError(f"Key '{key}' is not of expected type {expected_type.__name__} in permission set at index {idx}")

        # Additional check for 'PermissionSetName' to ensure it's a list of strings
        if not all(isinstance(item, str) for item in permission_set["PermissionSetName"]):
            raise ValueError(f"All items in 'PermissionSetName' must be strings in permission set at index {idx}")

def global_group_array_mapping(acct_list, global_file_contents,
                               current_aws_permission_sets,
                               pipeline_id):
    """Create global group mapping assignments"""
    logger.info("Starting global group assignement")

    # Validate the structure of the global file contents
    try:
        validate_permission_set_file_structure(global_file_contents)
    except (ValueError, TypeError) as e:
        logger.error("Validation error in global file contents: %s", e)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'message': str(e), 'type': 'JobFailed'}
        )
        return

    if global_file_contents:
        for account in acct_list:
            if account['Status'] != "SUSPENDED":
                for mapping in global_file_contents:
                    if mapping['TargetAccountid'].upper() == "GLOBAL":
                        try:
                            for each_perm_set_name in mapping['PermissionSetName']:
                                permission_set_arn = current_aws_permission_sets[each_perm_set_name]['Arn']
                                group_id = get_groupid(
                                    mapping['GlobalGroupName'])
                                if not group_id:
                                    logger.error(
                                        "Cannot assign permission set:%s.", mapping['GlobalGroupName'])
                                else:
                                    assignment_response = ic_admin.create_account_assignment(
                                        InstanceArn=ic_instance_arn,
                                        TargetId=str(account['Id']),
                                        TargetType='AWS_ACCOUNT',
                                        PrincipalType='GROUP',
                                        PermissionSetArn=permission_set_arn,
                                        PrincipalId=group_id
                                    )
                                    sleep(0.1)  # Aviod hitting API limit.
                                    logger.info("Performed global IAM Identity Center group assigment on \
                                                account: %s. Response:%s", account['Id'],
                                                assignment_response)
                        except ic_admin.exceptions.ThrottlingException as error:
                            logger.warning(
                                "%s. Hit IAM Identity Center API limit. Sleep 3s...", error)
                            sleep(3)
                        except ic_admin.exceptions.ConflictException as error:
                            logger.info("%s.The same create account assignment process has been \
                                        started in another invocation skipping.", error)
                            sleep(3)
                        except ClientError as error:
                            logger.error(
                                "Create global account assignment failed.%s.", error)
                            pipeline.put_job_failure_result(
                                jobId=pipeline_id,
                                failureDetails={
                                    'type': 'JobFailed', 'message': str(error)}
                            )
                    else:
                        logger.error("One of the assignments has incorrect \
                                     TargetAccount value: %s. Skipping this assignment.",
                                     mapping['TargetAccountid'])
    else:
        logger.info(
            "No global mapping information is loaded in existing files.")

def target_group_array_mapping(target_file_contents,
                               current_aws_permission_sets, pipeline_id):
    """Create target group mapping assignments"""
    logger.info("Starting target group assignement")
    if target_file_contents:
        try:
            for mapping in target_file_contents:
                for each_perm_set_name in mapping['PermissionSetName']:
                    for target_account_id in mapping['TargetAccountid']:
                        permission_set_arn = current_aws_permission_sets[each_perm_set_name]['Arn']
                        group_id = get_groupid(mapping['TargetGroupName'])
                        if not group_id:
                            logger.error("Cannot assign permission set to \
                                         group %s", mapping['TargetGroupName'])
                        else:
                            assignment_response = ic_admin.create_account_assignment(
                                InstanceArn=ic_instance_arn,
                                TargetId=str(target_account_id),
                                TargetType='AWS_ACCOUNT',
                                PrincipalType='GROUP',
                                PermissionSetArn=permission_set_arn,
                                PrincipalId=group_id
                            )
                            sleep(0.1)  # Aviod hitting API limit.
                            logger.info("Performed target IAM Identity Center group assigment on account %s.\
                                        Response: %s.", target_account_id, assignment_response)
        except ic_admin.exceptions.ThrottlingException as error:
            logger.warning(
                "%s. Hit IAM Identity Center API limit. Sleep 3s...", error)
            sleep(3)
        except ic_admin.exceptions.ConflictException as error:
            logger.info("%s. The same create account assignment process has been \
                        started in another invocation skipping.", error)
            sleep(3)
        except ClientError as error:
            logger.error("Create target account assignment failed.%s", error)
            pipeline.put_job_failure_result(
                jobId=pipeline_id,
                failureDetails={'type': 'JobFailed', 'message': str(error)}
            )
            quit()
    else:
        logger.info(
            "No target mapping information is loaded in existing files.")


def get_all_permission_sets(pipeline_id):
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
        skipped_perm_set = {}
        for perm_set_arn in ic_permission_sets:
            describe_perm_set = ic_admin.describe_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn
            )
            sleep(0.1)  # Aviod hitting API limit.
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
            permission_set_name_and_arn[perm_set_name] = {'Arn': perm_set_arn}
            logger.debug("%s", permission_set_name_and_arn)

    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning(
            "%s. Hit IAM Identity Center API limit. Sleep 3s...", error)
        sleep(3)
    except ClientError as error:
        logger.error("%s.", error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'type': 'JobFailed', 'message': str(error)}
        )
    print(f"Skipped Permission Set Name and ARN: {skipped_perm_set}")
    return permission_set_name_and_arn


def get_all_permission_sets_if_delegate(pipeline_id):
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

        skipped_perm_set = {}
        for perm_set_arn in ic_permission_sets:
            describe_perm_set = ic_admin.describe_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn
            )
            sleep(0.1)  # Aviod hitting API limit.
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
            print(
                f"Accounts for permission set {perm_set_arn} is {accounts_for_perm_set}")
            if management_account_id in accounts_for_perm_set:
                skipped_perm_set.update({perm_set_arn: perm_set_name})
                continue
            permission_set_name_and_arn[perm_set_name] = {'Arn': perm_set_arn}
            logger.debug("%s", permission_set_name_and_arn)

    except ic_admin.exceptions.ThrottlingException as error:
        logger.warning(
            "%s. Hit IAM Identity Center API limit. Sleep 3s...", error)
        sleep(3)
    except ClientError as error:
        logger.error("%s.", error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'type': 'JobFailed', 'message': str(error)}
        )
    print(f"Skipped Permission Set Name and ARN: {skipped_perm_set}")
    return permission_set_name_and_arn


def get_groupid(group_display_name):
    """Get the all the IAM Identity Center group names and ids"""
    try:
        response = identitystore_client.get_group_id(
            IdentityStoreId=identity_store_id,
            AlternateIdentifier= {
                'UniqueAttribute':
                {
                    'AttributePath': 'DisplayName',
                    'AttributeValue': str(group_display_name)
                }
            }
        )
        if response['GroupId'] == []:
            logger.error("Group %s does not exist.", group_display_name)
            group_id = None
        else:
            group_id = response['GroupId']
    except identitystore_client.exceptions.ThrottlingException as error:
        logger.warning("%s. Hit ListGroup API limit. Sleep 5s...", error)
        sleep(5)
    except ClientError as error:
        logger.error("%s", error)
    return group_id


def get_org_accounts():
    """Get all account ids from the current AWS Organizations"""
    try:
        response = orgs_client.list_accounts()
        org_accts = response['Accounts']
        while 'NextToken' in response:
            response = orgs_client.list_accounts(
                NextToken=response['NextToken']
            )
            org_accts += response['Accounts']
    except ClientError as error:
        logger.error("%s", error)
        org_accts = None
    return org_accts

def get_org_accounts_if_delegate():
    """Get all account ids from the current AWS Organizations"""
    try:
        response = orgs_client.list_accounts()
        org_accts = response['Accounts']
        while 'NextToken' in response:
            response = orgs_client.list_accounts(
                NextToken=response['NextToken']
            )
            org_accts += response['Accounts']
    except ClientError as error:
        logger.error("%s", error)
        org_accts = None

    org_accts = [acct for acct in org_accts if acct['Id'] != management_account_id]
    print(org_accts)
    return org_accts



def lambda_handler(event, context):
    """Lambda_handler"""
    logger.info(event)
    logger.debug(context)
    print(f"Delegated: {delegated}")


    try:
        sns_message_from_auto_perm = event['Records'][0]['Sns']['Message']
        if sns_message_from_auto_perm == 'AWS API Call via CloudTrail':
            pipeline_id = ''
        else:
            pipeline_id = sns_message_from_auto_perm
        logger.info("Start the Process, pipeline jobid is %s", pipeline_id)
        # Prepare account id.
        if delegated == 'true':
            acct_list = get_org_accounts_if_delegate()
        else:
            acct_list = get_org_accounts()
        logger.info(acct_list)
        # Check if Source files exist.
        global_file_contents = get_global_mapping_contents(
            ic_bucket_name, global_mapping_file_name, pipeline_id)
        target_file_contents = get_target_mapping_contents(
            ic_bucket_name, target_mapping_file_name, pipeline_id)
        logger.info("Loading mapping information from the files in s3...")
        # Get current account's permission set info.
        if delegated == "true":
            current_aws_permission_sets = get_all_permission_sets_if_delegate(
                pipeline_id)
            print("INFO: Admin delegated. Running in delegated admin account.")
        else:
            current_aws_permission_sets = get_all_permission_sets(pipeline_id)
            print("INFO: Admin NOT delegated. Running in Management account.")
        if not current_aws_permission_sets:
            logger.error(
                "Cannot load existing Permission Sets from AWS IAM Identity Center!")
            pipeline.put_job_failure_result(
                jobId=pipeline_id,
                failureDetails={
                    'type': 'JobFailed',
                    'message': "No Permission Set information!"
                })
            quit()
        else:
            logger.info("The current permision sets in this account:%s",
                        current_aws_permission_sets)
        # Use S3 mapping files(sycned from source) as the only source of truth.
        global_group_array_mapping(
                acct_list, global_file_contents, current_aws_permission_sets, pipeline_id)
        target_group_array_mapping(
            target_file_contents, current_aws_permission_sets, pipeline_id)
        all_assignments = list_all_current_account_assignment(
                acct_list, current_aws_permission_sets, pipeline_id)
        drift_detect_update(all_assignments, global_file_contents,
                            target_file_contents, current_aws_permission_sets, pipeline_id)
        # End of Assignment
        pipeline.put_job_success_result(jobId=pipeline_id)
        logger.info("Execution is complete.")

    except Exception as error:
        logger.error('%s', error)
        pipeline.put_job_failure_result(
            jobId=pipeline_id,
            failureDetails={'type': 'JobFailed', 'message': str(error)}
        )
