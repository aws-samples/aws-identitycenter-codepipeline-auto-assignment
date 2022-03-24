from __future__ import print_function
from cmath import log
import cfnresponse
import boto3, glob, json, os, logging
from botocore.exceptions import ClientError
from time import sleep
runtime_region = os.environ['Lambda_Region']
logger = logging.getLogger()
logger.setLevel(logging.INFO)

sso_admin = boto3.client('sso-admin',region_name=runtime_region)
identitystore_client = boto3.client('identitystore',region_name=runtime_region)
orgs_client = boto3.client('organizations', region_name=runtime_region)
s3client = boto3.client('s3',region_name=runtime_region)
pipeline = boto3.client('codepipeline',region_name=runtime_region)
SSOInstanceArn = os.environ.get('SSO_InstanceArn')
IdentityStoreId = os.environ.get('IdentityStore_Id')
BucketName = os.environ.get('SSO_S3_BucketName')
Global_mapping_file_name = os.environ.get('GlobalFileName')
Target_mapping_file_name = os.environ.get('TargetFileName')

# List all the current account assignment information
def list_all_current_account_assignment(acct_list,global_file_contents,target_file_contents,current_aws_permission_sets):
    all_assignments = []
    for each_perm_set_name in current_aws_permission_sets:
        try:
            for account in acct_list:
                if account['Status'] != "SUSPENDED":
                    account_assignment = sso_admin.list_account_assignments(
                                    InstanceArn= SSOInstanceArn ,
                                    AccountId=str(account['Id']),
                                    PermissionSetArn= current_aws_permission_sets[each_perm_set_name]['Arn'],
                                    MaxResults=100
                                    )
                    sleep(0.5)
                    #Eliminate the empty assignment responses.
                    if len(account_assignment['AccountAssignments']) != 0:
                        for each_assignment in account_assignment['AccountAssignments']:
                            ################################################################
                            # This Env only allows SSO 'GROUP' assignee rather than 'USER'.#
                            ################################################################
                            if str(each_assignment['PrincipalType']) == "USER":
                                delete_user_assignment = sso_admin.delete_account_assignment(
                                                InstanceArn=SSOInstanceArn,
                                                TargetId= each_assignment['AccountId'],
                                                TargetType='AWS_ACCOUNT',
                                                PermissionSetArn=each_assignment['PermissionSetArn'],
                                                PrincipalType=each_assignment['PrincipalType'],
                                                PrincipalId=each_assignment['PrincipalId']
                                            )
                                logger.info("PrincipalType 'USER' should not be used in SSO assignment, remove USER assignee:{} ".format(delete_user_assignment))

                            # After remove USER assignee, append all other GROUP assignee to the list
                            else:
                                all_assignments.append(each_assignment)
        except sso_admin.exceptions.ThrottlingException as e:
            logger.warning("{}.Hit SSO API limit. Sleep 3s...".format(e))
            sleep(3)
        except Exception as e:
            logger.error("{}".format(e))
    logger.info("Current GROUP assignments: {}".format(all_assignments))
    return all_assignments

def drift_detect_update(all_assignments,global_file_contents,target_file_contents,current_aws_permission_sets):
    check_list = all_assignments
    remove_list = []
    for each_assignment in check_list:
        try:
            logger.debug("list each global assignment:{}".format(each_assignment))
            for global_mapping in global_file_contents:
                for each_perm_set_name in global_mapping['PermissionSetName']:
                    global_group_id = get_groupid(global_mapping['GlobalGroupName'])
                    permission_set_arn = current_aws_permission_sets[each_perm_set_name]['Arn']
                    #Remove matched assignment from list:
                    if each_assignment['PrincipalId'] == global_group_id and each_assignment["PermissionSetArn"] == permission_set_arn:
                        remove_list.append(each_assignment)
        except sso_admin.exceptions.ThrottlingException as e:
            logger.warning("{}.Hit SSO API limit. Sleep 3s...".format(e))
            sleep(3)
        except Exception as e:
            logger.error("{}".format(e))

    for each_assignment in check_list:
        try:
            for target_mapping in target_file_contents:
                #logger.info("list each target_file_contents ", target_file_contents)
                if each_assignment['AccountId'] in target_mapping['TargetAccountid']:
                    for each_perm_set_name in target_mapping['PermissionSetName']:
                        permission_set_arn = current_aws_permission_sets[each_perm_set_name]['Arn']
                        target_group_id = get_groupid(target_mapping['TargetGroupName'])
                    if each_assignment['PrincipalId'] == target_group_id and each_assignment['PermissionSetArn'] == permission_set_arn:
                        remove_list.append(each_assignment)
        except sso_admin.exceptions.ThrottlingException as e:
            logger.warning("{}.Hit SSO API limit. Sleep 3s...".format(e))
            sleep(3)
        except Exception as e:
            logger.error("{}".format(e) )

    for item in remove_list:
        check_list.remove(item)
    #Search drift by checking the element that remain in check_list.
    if len(check_list) == 0:
        logger.info("SSO assignments has been applied. No drift was found within current assignments :)")
    else:
        for delta_assignment in check_list:
            try:
                delete_user_assignment = sso_admin.delete_account_assignment(
                                            InstanceArn=SSOInstanceArn,
                                            TargetId= delta_assignment['AccountId'],
                                            TargetType='AWS_ACCOUNT',
                                            PermissionSetArn= delta_assignment['PermissionSetArn'],
                                            PrincipalType='GROUP',
                                            PrincipalId=delta_assignment['PrincipalId']
                                        )
                logger.warning("Warning. Drift has been detected and removing..{}".format(delete_user_assignment))
            except sso_admin.exceptions.ThrottlingException as e:
                logger.warning("{}.Hit API limits. Sleep 3s...".format(e))
                sleep(3)
            except Exception as e:
                logger.error("Error. ".format(e) )

def get_global_mapping_contents(bucketname,global_mapping_file_name):
    try:
        filedata = s3client.get_object(
                   Bucket=bucketname,
                   Key=global_mapping_file_name
                )
        content = filedata['Body']
        jsonObject = json.loads(content.read())
        return jsonObject
    except Exception as e:
        logger.warning("Cannot get global mapping information.Did you upload the global mapping file?{}".format(e))
        #Exit to prevent accidently wiping out all the attachment
        quit()

def get_target_mapping_contents(bucketname,target_mapping_file_name):
    try:
        filedata = s3client.get_object(
                   Bucket=bucketname,
                   Key=target_mapping_file_name
                )
        content = filedata['Body']
        jsonObject = json.loads(content.read())
        return jsonObject
    except Exception as e:
        logger.warning("Cannot get target mapping information. Did you upload the target mapping file?{}".format(e))
        quit()

def global_group_array_mapping(acct_list,global_file_contents,current_aws_permission_sets):
    if global_file_contents is not None:
        for account in acct_list:
            if account['Status'] != "SUSPENDED":
                for mapping in global_file_contents:
                    sleep(0.5)
                    if mapping['TargetAccountid'].upper() == "GLOBAL" :
                        try:
                            for each_perm_set_name in mapping['PermissionSetName']:
                                permission_set_arn = current_aws_permission_sets[each_perm_set_name]['Arn']
                                group_id = get_groupid(mapping['GlobalGroupName'])
                                if group_id is None:
                                    logger.error("Cannot assign permission set.".format(mapping['GlobalGroupName']))
                                else:
                                    assignment_response = sso_admin.create_account_assignment(
                                            InstanceArn = SSOInstanceArn,
                                            TargetId = str(account['Id']),
                                            TargetType = 'AWS_ACCOUNT',
                                            PrincipalType='GROUP',
                                            PermissionSetArn = permission_set_arn,
                                            PrincipalId=group_id
                                            )
                                    sleep(0.5)
                                    logger.info("Performed global SSO group assigment on account: {}. Response:{}".format(account['Id'],assignment_response))
                        except sso_admin.exceptions.ThrottlingException as e:
                            logger.warning("{}.Hit SSO API limit. Sleep 3s...".format(e))
                            sleep(3)
                        except sso_admin.exceptions.ConflictException as e:
                            logger.info("{}.The same create account assignment process has been started in another invocation skipping.".format(e))
                            sleep(1)
                        except ClientError as e:
                            logger.error("Create global account assignment failed.".format(e))
                    else:
                        logger.warning("The {} assignment has a non-global value.".format(mapping['TargetAccountid']))
    else:
        logger.info("No global mapping information is loaded in existing files.")

def target_group_array_mapping(target_file_contents,current_aws_permission_sets):
    if target_file_contents is not None:
        try:
            for mapping in target_file_contents:
                for each_perm_set_name in mapping['PermissionSetName']:
                    sleep(0.5)
                    for target_account_id in mapping['TargetAccountid']:
                        permission_set_arn = current_aws_permission_sets[each_perm_set_name]['Arn']
                        group_id = get_groupid(mapping['TargetGroupName'])
                        if group_id is None:
                            logger.error("Cannot assign permission set to group {}".format(mapping['TargetGroupName']))
                        else:
                            assignment_response = sso_admin.create_account_assignment(
                                    InstanceArn = SSOInstanceArn,
                                    TargetId = str(target_account_id),
                                    TargetType = 'AWS_ACCOUNT',
                                    PrincipalType='GROUP',
                                    PermissionSetArn = permission_set_arn,
                                    PrincipalId=group_id
                                    )
                            sleep(0.5)
                            logger.info("Performed target SSO group assigment on account {}.Response:{}".format(target_account_id,assignment_response))
        except sso_admin.exceptions.ThrottlingException as e:
            logger.warning("{}Hit SSO API limit. Sleep 3s...".format(e))
            sleep(3)
        except sso_admin.exceptions.ConflictException as e:
            logger.info("{}.The same create account assignment process has been started in another invocation skipping.".format(e))
            sleep(1)
        except ClientError as e:
            logger.error("Create target account assignment failed.".format(e))
            raise
    else:
        logger.info("No target mapping information is loaded in existing files.")

# List all the permission sets for the SSO ARN
def get_all_permission_sets():
    permission_set_name_and_arn = {}
    try:
        sso_permission_sets = sso_admin.list_permission_sets(
            InstanceArn=SSOInstanceArn,
            MaxResults=100 
            )
        for perm_set_arn in sso_permission_sets['PermissionSets']:
            describe_perm_set = sso_admin.describe_permission_set(
                InstanceArn=SSOInstanceArn,
                PermissionSetArn=perm_set_arn
            )
            sleep(0.5)
            perm_set_name = describe_perm_set['PermissionSet']['Name']
            perm_set_arn = describe_perm_set['PermissionSet']['PermissionSetArn']
            permission_set_name_and_arn[perm_set_name] = {'Arn': perm_set_arn}
            logger.debug("{}".format(permission_set_name_and_arn))
        return permission_set_name_and_arn
    except sso_admin.exceptions.ThrottlingException as e:
        logger.warning("{}.Hit SSO API limit. Sleep 3s...".format(e))
        sleep(3)
    except ClientError as e:
        logger.error("{}.".format(e))
# Get the all the SSO group Namd and GroupId
def get_groupid(GroupDisplayName):
    try:
        response = identitystore_client.list_groups(
                    IdentityStoreId=IdentityStoreId,
                    Filters=[
                        {
                            'AttributePath': 'DisplayName',
                            'AttributeValue': str(GroupDisplayName)
                        },
                    ]
                )
        #logger.info("debug. get_groupid response:", response)
        if response['Groups'] == []:
            logger.error("{} does not exist.".format(str(GroupDisplayName)))
            return None
        else:
            group_id = response['Groups'][0]['GroupId']
            return group_id
    except identitystore_client.exceptions.ThrottlingException as e:
        logger.warning("{}Hit ListGroup API limit. Sleep 5s...".format(e))
        sleep(5)
    except ClientError as e:
        logger.error("{}".format(e))
#Lambda_handler
def lambda_handler(event, context):
    logger.info("{}".format(event))
    try: 
        if 'RequestType' in event:
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
        else:
            sns_message = event['Records'][0]['Sns']['Message']
            logger.info("Start the Process, pipeline jobid is {}".format(sns_message))
            #Prepare account id 
            org_list_accounts = orgs_client.list_accounts()
            acct_list = []
            acct_list = org_list_accounts['Accounts']
            #Check if Source files exist
            global_file_contents = get_global_mapping_contents(BucketName,Global_mapping_file_name)
            target_file_contents = get_target_mapping_contents(BucketName,Target_mapping_file_name)
            logger.info("Loading mapping information from the files in s3...")
            #Get current account's permission set info
            current_aws_permission_sets = get_all_permission_sets()
            if current_aws_permission_sets is None:
                logger.error("Cannot load permission set information")
                quit()
            else:
                logger.info("all the current permision set info:{}".format(current_aws_permission_sets))

            # Use S3 mapping files(sycned from source) as the only source of truth.
            global_group_array_mapping(acct_list,global_file_contents,current_aws_permission_sets)
            target_group_array_mapping(target_file_contents,current_aws_permission_sets)

            all_assignments = list_all_current_account_assignment(acct_list,global_file_contents,target_file_contents,current_aws_permission_sets)
            drift_detect_update(all_assignments,global_file_contents,target_file_contents,current_aws_permission_sets)
            # End of Assignment
            pipeline.put_job_success_result(jobId=sns_message)
            logger.info("Execution is complete.")
    except Exception as e:
        logger.error('{}'.format(e))
        pipeline.put_job_failure_result(
            jobId=sns_message,
            failureDetails={'type': 'JobFailed','message':str(e)}
            )
