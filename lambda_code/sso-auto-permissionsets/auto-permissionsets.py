# Import boto3 for AWS calls, glob for reading the JSON files, and json for parsing the JSON
import boto3, glob, json, os, time, logging
from time import sleep
from botocore.exceptions import ClientError
import cfnresponse
runtime_region = os.environ['Lambda_Region']
# Declare boto3 client. Use us-east-1 by default
s3 = boto3.resource('s3')
sso_admin = boto3.client('sso-admin',region_name=runtime_region)
sns_client = boto3.client('sns',region_name=runtime_region)
pipeline = boto3.client('codepipeline',region_name=runtime_region)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

#Load external variables 
sso_instance_arn = os.environ.get('SSO_InstanceArn')
bucket_name = os.environ.get('SSO_S3_BucketName')
sns_topic_name=os.environ.get('SNS_Topic_Name')

# List all the permission sets for the SSO ARN
def get_all_permission_sets():
    permission_set_name_and_arn = {}
    try:
        listed_permission_set_arns = sso_admin.list_permission_sets(
            InstanceArn=sso_instance_arn,
            MaxResults=100
        )

        for perm_set_arn in listed_permission_set_arns['PermissionSets']:
            describe_perm_set = sso_admin.describe_permission_set(
                InstanceArn=sso_instance_arn,
                PermissionSetArn=perm_set_arn
            )
            sleep(0.2)
            try: 
                description = describe_perm_set['PermissionSet']['Description']
            except KeyError:
                description = ''
            perm_set_name = describe_perm_set['PermissionSet']['Name']
            perm_set_arn = describe_perm_set['PermissionSet']['PermissionSetArn']
            permission_set_name_and_arn[perm_set_name] = {'Arn': perm_set_arn, 'Description': description}     
        return permission_set_name_and_arn
    except sso_admin.exceptions.ThrottlingException as e:
        logger.warning("Hit SSO API limits. Sleep 5s...{}".format(e))
        sleep(5)
    except sso_admin.exceptions.ConflictException as e:
        logger.info("The same SSO process has been started in another invocation, skipping...{}".format(e))
        sleep(2)
    except ClientError as e:
        logger.error("{}".format(e))

# Download all the JSON files in the from "permission-sets/" folder in S3 bucket 
def get_all_json_files(bucket_name):
    file_contents = {}
    my_bucket = s3.Bucket(bucket_name)
    try:
        for s3_object in my_bucket.objects.filter(Prefix="permission-sets/"):
            if ".json" in s3_object.key:
                file_name=s3_object.key
                logger.info("processing file: {}".format(file_name) )
                s3.Bucket(bucket_name).download_file(file_name, "/tmp/each_permission_set.json")
                f = open("/tmp/each_permission_set.json")
                data = json.load(f)
                file_contents[file_name] = data
                logger.debug("File data: {}".format(data))
                f.close()
        return file_contents
    except Exception as e:
        logger.error("Cannot load permission set content from s3 file {} ".format(file_name))

# Create a permission set in AWS SSO
def create_permission_set(name, desc, tags):
    try:
        create_permission_set = sso_admin.create_permission_set(
            Name=name,
            Description=desc,
            InstanceArn=sso_instance_arn,
            Tags=tags
        )
        sleep(0.2)
        return create_permission_set
    except sso_admin.exceptions.ThrottlingException as e:
        logger.warning("{}Hit CreatePermissionSet API limits. Sleep 5s...".format(e))
        sleep(5)
    except sso_admin.exceptions.ConflictException as e:
        logger.info("{}The same SSO process has been started in another invocation, skipping....".format(e))
        sleep(2)
    except ClientError as e:
        logger.error("{}".format(e))

# Attach a managed policy to a permission set
def add_managed_policy_to_perm_set(perm_set_arn, managed_policy_arn):
    try:
        attach_managed_policy = sso_admin.attach_managed_policy_to_permission_set(
            InstanceArn=sso_instance_arn,
            PermissionSetArn=perm_set_arn,
            ManagedPolicyArn=managed_policy_arn
        )
        logger.info('Managed Policy {} added to {}'.format(managed_policy_arn, perm_set_arn))
        sleep(0.2)
        return attach_managed_policy
    except sso_admin.exceptions.ThrottlingException as e:
        logger.warning("{}.Hit API limits. Sleep 2s...".format(e))
        sleep(2)
    except sso_admin.exceptions.ConflictException as e:
        logger.info("{}.The same SSO process has been started in another invocation, skipping....".format(e))
    except ClientError as e:
        logger.error("{}".format(e))

# Remove a managed policy from a permission set
def remove_managed_policy_from_perm_set(perm_set_arn, managed_policy_arn):
    try:
        remove_managed_policy = sso_admin.detach_managed_policy_from_permission_set(
            InstanceArn=sso_instance_arn,
            PermissionSetArn=perm_set_arn,
            ManagedPolicyArn=managed_policy_arn
        )
        logger.info('Managed Policy {} removed from {}'.format(managed_policy_arn, perm_set_arn))
        sleep(0.2)
        return remove_managed_policy
    except sso_admin.exceptions.ThrottlingException as e:
        logger.warning("{}.Hit API limits. Sleep 2s...".format(e))
        sleep(2)  
    except sso_admin.exceptions.ConflictException as e:
        logger.info("{}.The same SSO process has been started in another invocation, skipping...".format(e))
    except ClientError as e:
        logger.error("{}".format(e))

# Synchronize Managed Polcieis as defined in the JSON file with AWS
def sync_managed_policies(perm_set_name, local_managed_policies, perm_set_arn):
    # Declare arrays for keeping track on Managed policies locally and on AWS
    aws_managed_attached_names = []
    aws_managed_attached_dict = {}
    local_policy_names = []
    local_policy_dict = {}

    # Get all the managed polcies attached to the permission set
    try:
        list_managed_policies = sso_admin.list_managed_policies_in_permission_set(
            InstanceArn=sso_instance_arn,
            PermissionSetArn=perm_set_arn
        )
        sleep(0.2)
    except sso_admin.exceptions.ThrottlingException as e:
        logger.warning("{}.Hit SSO API limits. Sleep 5s...".format(e))
        sleep(5)
    except sso_admin.exceptions.ConflictException as e:
        logger.info("{}.The same SSO process has been started in another invocation, skipping...".format(e))
        sleep(2)
    except ClientError as e:
        logger.error("{}".format(e))

    # Populate arrays for Managed Policy tracking
    for aws_managed_policy in list_managed_policies['AttachedManagedPolicies']:
        aws_managed_attached_names.append(aws_managed_policy['Name'])
        aws_managed_attached_dict[aws_managed_policy['Name']] = aws_managed_policy['Arn']

    for local_managed_policy in local_managed_policies:
        local_policy_names.append(local_managed_policy['Name'])
        local_policy_dict[local_managed_policy['Name']] = local_managed_policy['Arn']

    for policy_name in local_policy_names:
        if not policy_name in aws_managed_attached_names:
            add_managed_policy_to_perm_set(perm_set_arn, local_policy_dict[policy_name])

    for aws_policy in aws_managed_attached_names:
        if not aws_policy in local_policy_names:
            remove_managed_policy_from_perm_set(perm_set_arn, aws_managed_attached_dict[aws_policy])

# Remove Inline policies from permission set if they exist
def remove_inline_policies(perm_set_arn):
    try:
        list_existing_inline = sso_admin.get_inline_policy_for_permission_set(
            InstanceArn=sso_instance_arn,
            PermissionSetArn=perm_set_arn
        )

        if list_existing_inline['InlinePolicy']:
            delete_exiting_inline = sso_admin.delete_inline_policy_from_permission_set(
                InstanceArn=sso_instance_arn,
                PermissionSetArn=perm_set_arn
            )
            logger.info('Removed inline policiy for {}'.format(perm_set_arn))
            sleep(0.2)
    except sso_admin.exceptions.ThrottlingException as e:
        logger.warning("{}.Hit SSO API limit. Sleep 5s..".format(e))
        sleep(5)
    except sso_admin.exceptions.ConflictException as e:
        logger.info("{}.The same SSO process has been started in another invocation, skipping...".format(e))
        sleep(2)
    except ClientError as e:
        logger.error("{}".format(e))

# Synchronize Inline Policies as define in the JSON file with AWS
def sync_inline_policies(perm_set_name, local_inline_policy, perm_set_arn):
    if local_inline_policy:
        try:
            logger.info('Synchronizing inline policy with {}'.format(perm_set_arn))
            put_inline_policy = sso_admin.put_inline_policy_to_permission_set(
                InstanceArn=sso_instance_arn,
                PermissionSetArn=perm_set_arn,
                InlinePolicy=json.dumps(local_inline_policy)
            )
            sleep(0.2)
            return put_inline_policy
        except sso_admin.exceptions.ThrottlingException as e:
            logger.warning("{}.Hit SSO API limit. Sleep 5s...".format(e))
            sleep(5)
        except sso_admin.exceptions.ConflictException as e:
            logger.info("{}.The same SSO process has been started in another invocation, skipping...".format(e))
        except ClientError as e:
            logger.warn("{}".format(e))
    else:
        remove_inline_policies(perm_set_arn)

# Delete permission set from AWS
def delete_permission_set(perm_set_arn, perm_set_name):
    try:
        delete_perm_set = sso_admin.delete_permission_set(
            InstanceArn=sso_instance_arn,
            PermissionSetArn=perm_set_arn
        )
        logger.info('{} Permission set deleted'.format(perm_set_name))
        sleep(0.2)
        return delete_perm_set
    except sso_admin.exceptions.ThrottlingException as e:
        logger.warning("{}.Hit delete_permission_set API limits. Sleep 5s..".format(e))
        sleep(5)
    except sso_admin.exceptions.ConflictException as e:
        logger.info("{}.The same SSO process has been started in another invocation, skipping...".format(e))
    except ClientError as e:
        logger.warn("{}".format(e))

# Synchronize the description between the JSON file and AWS
def sync_description(local_name, perm_set_arn, local_desc, aws_desc):
    if not local_desc == aws_desc:
        logger.info('Updating description for {}'.format(perm_set_arn))
        update_perm_set = sso_admin.update_permission_set(
            InstanceArn=sso_instance_arn,
            PermissionSetArn=perm_set_arn,
            Description=local_desc
        )
        sleep(0.2)

# Add tags to the permission set
def tag_permission_set(local_name, local_tags, perm_set_arn):
    try:
        add_tags = sso_admin.tag_resource(
            InstanceArn=sso_instance_arn,
            ResourceArn=perm_set_arn,
            Tags=local_tags
        )
        logger.info('Tags added to or updated for {}'.format(local_name))
    except ClientError as e:
        logger.error("{}".format_map(e))

# Remove tags from a permission set
def remove_tag(key, perm_set_arn, local_name):
    try:
        remove_tag = sso_admin.untag_resource(
            InstanceArn=sso_instance_arn,
            ResourceArn=perm_set_arn,
            TagKeys=[
                key,
            ]
        )
        logger.info('Tag removed from {}'.format(local_name))
    except ClientError as e:
        logger.error("{}.".format(e))

# Synchronize the tags between the JSON and AWS
def sync_tags(local_name, local_tags, perm_set_arn):
    try:
        list_tags = sso_admin.list_tags_for_resource(
            InstanceArn=sso_instance_arn,
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
                
    except sso_admin.exceptions.ThrottlingException as e:
        logger.warning("{}.Hit ListTags API limits. Sleep 3s...".format(e))
        sleep(3)
    except ClientError as e:
        logger.error("{}".format(e))

# List all the accounts for a given permission set
def get_accounts_by_perm_set(perm_set_arn):
    try:
        list_accounts = sso_admin.list_accounts_for_provisioned_permission_set(
            InstanceArn=sso_instance_arn,
            PermissionSetArn=perm_set_arn
        )

        return list_accounts['AccountIds']
    except sso_admin.exceptions.ThrottlingException as e:
        logger.warning("{}.Hit ListAccountsForProvisionedPermissionSet API limits. Sleep 5s...".format(e))
        sleep(5)
    except ClientError as e:
        logger.error("{}".format(e))

# Remove any provisioned accounts and User / Group assignments for the account associated with a permission set
def deprovision_permission_set_from_accounts(perm_set_arn, perm_set_name):
    try:
        account_ids = get_accounts_by_perm_set(perm_set_arn)
        # If the list of accounts is not null - remove all of the assignments
        if account_ids:
            for account in account_ids:
                # Grab all of the assignments for the permission set
                list_assignment = sso_admin.list_account_assignments(
                    InstanceArn=sso_instance_arn,
                    AccountId=account,
                    PermissionSetArn=perm_set_arn
                )
                # Remove all of the identified assignments for permission set
                for assignment in list_assignment['AccountAssignments']:
                    logger.info('Deleting assignment for account: {}, principal-type: {}, principal-id: {}'.format(account, assignment['PrincipalType'], assignment['PrincipalId']))
                    delete_assignment = sso_admin.delete_account_assignment(
                        InstanceArn=sso_instance_arn,
                        TargetId=account,
                        TargetType='AWS_ACCOUNT',
                        PermissionSetArn=perm_set_arn,
                        PrincipalType=assignment['PrincipalType'],
                        PrincipalId=assignment['PrincipalId']
                    )
                    sleep(1) # Allow time for the deprovision - this should be refactored to be event driven
        else:
            logger.info('{} is not provisioned to any accounts - deleting...'.format(perm_set_name))
    except sso_admin.exceptions.ThrottlingException as e:
        logger.warning("{}.Hit API limits. Sleep 5s...".format(e))
        sleep(5)    
    except sso_admin.exceptions.ConflictException as e:
        logger.info("{}.The same SSO process has been started in another invocation, skipping...".format(e))
        sleep(2)
    except ClientError as e:
        logger.error("{}".format(e))

# Reprovision the drifted permission sets
def reprovision_permission_sets(perm_set_name, perm_set_arn):
    account_ids = get_accounts_by_perm_set(perm_set_arn)
    outdated_accounts = []
    # Look through the accounts to see if the permission set is not current and populate an array if any are found
    for account in account_ids:
        try:
            outdated_perm_sets = sso_admin.list_permission_sets_provisioned_to_account(
                InstanceArn=sso_instance_arn,
                AccountId=account,
                ProvisioningStatus='LATEST_PERMISSION_SET_NOT_PROVISIONED'
            )
            sleep(0.2)
            if outdated_perm_sets['PermissionSets']:
                outdated_accounts.append(outdated_perm_sets['PermissionSets'])
        except sso_admin.exceptions.ThrottlingException as e:
            logger.warning("{}.Hit API limits. Sleep 5s...".format(e))
            sleep(5)                 
        except sso_admin.exceptions.ConflictException as e:
            logger.info("{}The same SSO process has been started in another invocation, skipping...".format(e))
            sleep(2)
        except ClientError as e:
            logger.error("{}".format(e))
    
    # If any accounts were found to be out of date - reprovision the permission set to all accounts
        # This can be done on an account by account level, but we'd have to monitor the status of every provision
    if outdated_accounts:
        try:
            logger.info('Reprovisioning {} for the following accounts: {}'.format(perm_set_name, account_ids))
            provision_perm_set = sso_admin.provision_permission_set(
                InstanceArn=sso_instance_arn,
                PermissionSetArn=perm_set_arn,
                TargetType='ALL_PROVISIONED_ACCOUNTS'
            )
            sleep(1)
            # Find any IN_PROGRESS provisioning operations
            get_provisionsing_status = sso_admin.list_permission_set_provisioning_status(
                InstanceArn=sso_instance_arn,
                Filter={
                    'Status': 'IN_PROGRESS'
                }
            )
            # Monitor the provisioning operation until it is no longer IN_PROGRESS
            complete = 'false'
            for status in get_provisionsing_status['PermissionSetsProvisioningStatus']:
                while complete == 'false':
                    provision_status = sso_admin.describe_permission_set_provisioning_status(
                        InstanceArn=sso_instance_arn,
                        ProvisionPermissionSetRequestId=status['RequestId']
                    )
                    if provision_status['PermissionSetProvisioningStatus']['Status'] == 'IN_PROGRESS':
                        logger.info('provisioning in progress...')
                        sleep(5)
                    else: 
                        complete = 'true'
        except sso_admin.exceptions.ThrottlingException as e:
            logger.warning("{}Hit API limits. Sleep 5s...".format(e))
            sleep(5)   
        except sso_admin.exceptions.ConflictException as e:
            logger.info("The same SSO process has been started in another invocation, skipping...".format(e))
            sleep(2)
        except ClientError as e:
            logger.error("{}".format(e))

# Synchronize the local JSON files with the AWS Permission Sets
def sync_json_with_aws(local_files, aws_permission_sets):
    local_permission_set_names = []
    try:
        for local_file in local_files:
            local_permission_set = local_files[local_file]
            local_name = local_permission_set['Name']
            local_desc = local_permission_set['Description']
            local_tags = local_permission_set['Tags']
            local_managed_policies = local_permission_set['ManagedPolicies']
            local_inline_policy = local_permission_set['InlinePolicies']
            local_permission_set_names.append(local_name)
            # If Permission Set does not exist in AWS - add it
            if local_name in aws_permission_sets:
                logger.info('{} exists in SSO - checking policy and configuration'.format(local_name))
            else:
                logger.info('ADD OPERATION: {} does not exist in SSO - adding...'.format(local_name))
                created_perm_set = create_permission_set(local_name, local_desc, local_tags)
                created_perm_set_name = created_perm_set['PermissionSet']['Name']
                created_perm_set_arn = created_perm_set['PermissionSet']['PermissionSetArn']
                created_perm_set_desc = created_perm_set['PermissionSet']['Description']
                aws_permission_sets[created_perm_set_name] = {'Arn': created_perm_set_arn, 'Description': created_perm_set_desc}

            # Synchronize managed and inline policies for all local permission sets with AWS
            sync_managed_policies(local_name, local_managed_policies, aws_permission_sets[local_name]['Arn'])
            sync_inline_policies(local_name, local_inline_policy, aws_permission_sets[local_name]['Arn'])
            sync_description(local_name, aws_permission_sets[local_name]['Arn'], local_desc, aws_permission_sets[local_name]['Description'])
            sync_tags(local_name, local_tags, aws_permission_sets[local_name]['Arn'])
            reprovision_permission_sets(local_name, aws_permission_sets[local_name]['Arn'])

        # If permission set exists in AWS but not on the local - delete it
        for aws_perm_set in aws_permission_sets:
            if not aws_perm_set in local_permission_set_names:
                logger.info('DELETE OPERATION: {} does not exist locally - deleting...'.format(aws_perm_set))
                deprovision_permission_set_from_accounts(aws_permission_sets[aws_perm_set]['Arn'], aws_perm_set)
                delete_permission_set(aws_permission_sets[aws_perm_set]['Arn'], aws_perm_set)
    except ClientError as e:
        logger.error("{}.Sync AWS permission sets failed".format(e))

def invoke_auto_assignment(sns_topic_name,accountid,pipeline_job_id):
    if pipeline_job_id:
        try:
            topic_arn ='arn:aws:sns:'+runtime_region+':'+str(accountid)+':'+sns_topic_name
            msg = ""
            response = sns_client.publish(
                        TopicArn=topic_arn,
                        Message=pipeline_job_id
                        )
        except Exception as e:
            logger.error("{}".format(e))

def lambda_handler(event, context):
    logger.info(event)
    if 'RequestType' in event and event['RequestType'] == 'Delete':
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
    elif 'CodePipeline.job' in event or event['detail-type'] =='AWS API Call via CloudTrail':
        try:
            logger.info("The automation process is now started...")
            aws_permission_sets = get_all_permission_sets()
            logger.info("The existing aws_permission_sets: {}".format(aws_permission_sets))
            #Get the  permission set baseline by loading S3 bucket files
            json_files = get_all_json_files(bucket_name)
            sync_json_with_aws(json_files, aws_permission_sets)                      
            ##Invoke Next automation lambda function
            logger.info("Published sns topic to invoke auto assignment function. Check the auto assignment lambda funcion log for further execution details.")
            accountid=context.invoked_function_arn.split(':')[4]
            invoke_auto_assignment(sns_topic_name,accountid,event['CodePipeline.job']['id'])
        except Exception as e:
            pipeline.put_job_failure_result(
                jobId=event['CodePipeline.job']['id'],
                failureDetails={'message':str(e), 'type': 'JobFailed'}
            )
