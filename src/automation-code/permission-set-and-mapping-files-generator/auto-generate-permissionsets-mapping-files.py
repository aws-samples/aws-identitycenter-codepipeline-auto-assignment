"""Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved"""
"""
This script fetches existing permission sets and assignments from AWS IAM Identity Center
and creates the corresponding JSON files in the identity-center-mapping-info directory structure.
"""


from typing import Dict, List, Set, Tuple
from botocore.config import Config
import os
import json
import boto3
import logging
from time import sleep
from botocore.exceptions import ClientError
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Stream handler to print logs on screen
console_handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

boto_logger = logging.getLogger('botocore')
boto_logger.setLevel(logging.DEBUG)


for handler in logger.handlers:
    boto_logger.addHandler(handler)


class RetryFilter(logging.Filter):
    def filter(self, record):
        return 'Retry needed' in record.getMessage()


boto_logger.addFilter(RetryFilter())

AWS_CONFIG = Config(
    retries=dict(
        max_attempts=100,
        mode='adaptive'
    )
)

runtime_region = os.getenv('AWS_REGION')
ic_admin = boto3.client(
    'sso-admin', region_name=runtime_region, config=AWS_CONFIG)
identitystore_client = boto3.client(
    'identitystore', region_name=runtime_region, config=AWS_CONFIG)
sts_client = boto3.client(
    'sts', region_name=runtime_region, config=AWS_CONFIG)
organizations = boto3.client('organizations', config=AWS_CONFIG)
ic_instance_arn = os.getenv('IC_INSTANCE_ARN')
identity_store_id = os.getenv('IDENTITY_STORE_ID')


# Global variables to store delegated admin status and management account ID
IS_DELEGATED = None
MANAGEMENT_ACCOUNT_ID = None
skip_management_perm_sets = set()


def initialize_global_vars():
    """Initialize global variables for delegated admin status and management account ID"""
    global IS_DELEGATED, MANAGEMENT_ACCOUNT_ID, skip_management_perm_sets
    skip_management_perm_sets = set()
    try:
        org_response = organizations.describe_organization()
        MANAGEMENT_ACCOUNT_ID = org_response['Organization']['MasterAccountId']
        IS_DELEGATED = sts_client.get_caller_identity(
        )['Account'] != MANAGEMENT_ACCOUNT_ID
        if IS_DELEGATED:
            logger.info("Running in delegated admin account")
    except Exception as e:
        logger.error(f"Error initializing global variables: {str(e)}")
        IS_DELEGATED = False
        MANAGEMENT_ACCOUNT_ID = None


console_handler.setLevel(logging.INFO)


def get_permission_set_details(perm_set_arn):
    """Get detailed information about a permission set including policies and tags"""
    logger.info(f"Getting details for permission set: {perm_set_arn}")
    try:
        describe_perm_set = ic_admin.describe_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )
        perm_set = describe_perm_set['PermissionSet']
        sleep(0.1)

        managed_policies = []

        paginator = ic_admin.get_paginator(
            'list_managed_policies_in_permission_set')
        for page in paginator.paginate(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        ):
            for policy in page.get('AttachedManagedPolicies', []):
                managed_policies.append({
                    "Name": policy['Name'],
                    "Arn": policy['Arn']
                })
            sleep(0.1)

        # Get customer managed policies if they exist
        customer_managed_policies = []
        try:
            paginator = ic_admin.get_paginator(
                'list_customer_managed_policy_references_in_permission_set')
            for page in paginator.paginate(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn
            ):
                for policy in page.get('CustomerManagedPolicyReferences', []):
                    customer_managed_policies.append({
                        "Name": policy['Name'],
                        "Path": policy.get('Path', '/')
                    })
                sleep(0.1)
        except ic_admin.exceptions.ResourceNotFoundException:
            pass

        # Get permissions boundary if it exists
        try:
            boundary = ic_admin.get_permissions_boundary_for_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn
            ).get('PermissionsBoundary', None)
            if boundary:
                boundary_details = {}
                if 'ManagedPolicyArn' in boundary:
                    boundary_details['Arn'] = boundary['ManagedPolicyArn']
                    if '/' in boundary['ManagedPolicyArn']:
                        boundary_details['Name'] = boundary['ManagedPolicyArn'].split(
                            '/')[-1]
                if 'CustomerManagedPolicyReference' in boundary:
                    boundary_details['Name'] = boundary['CustomerManagedPolicyReference']['Name']
                    boundary_details['Path'] = boundary['CustomerManagedPolicyReference'].get(
                        'Path', '/')
            else:
                boundary_details = None
            sleep(0.1)
        except ic_admin.exceptions.ResourceNotFoundException:
            boundary_details = None

        # Get inline policy if it exists
        try:
            inline_policy = ic_admin.get_inline_policy_for_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn
            ).get('InlinePolicy', None)
            sleep(0.1)
        except ic_admin.exceptions.ResourceNotFoundException:
            inline_policy = None

        # Get tags
        tags_response = ic_admin.list_tags_for_resource(
            InstanceArn=ic_instance_arn,
            ResourceArn=perm_set_arn
        )

        all_tags = tags_response.get('Tags', [])

        while 'NextToken' in tags_response:
            tags_response = ic_admin.list_tags_for_resource(
                InstanceArn=ic_instance_arn,
                NextToken=tags_response['NextToken'],
                ResourceArn=perm_set_arn
            )
            all_tags.extend(tags_response.get('Tags', []))

        sleep(0.1)

        # Create permission set JSON
        perm_set_json = {
            "Name": perm_set['Name'],
            "Description": perm_set.get('Description', perm_set['Name']),
            "Session_Duration": perm_set.get('SessionDuration', 'PT1H'),
            "Tags": all_tags,
            "ManagedPolicies": managed_policies,
            "CustomerPolicies": customer_managed_policies,
            "InlinePolicies": json.loads(inline_policy) if inline_policy else []
        }

        if boundary_details:
            perm_set_json["PermissionsBoundary"] = boundary_details

        return perm_set_json

    except Exception as e:
        logger.error(
            f"Error getting permission set details for {perm_set_arn}: {str(e)}")
        raise


def get_group_name(group_id, identity_store_id, group_display_names):
    """Get group display name from cache or Identity Store"""
    if group_id in group_display_names:
        return group_display_names[group_id]

    try:
        # Get group details from Identity Store
        group_response = identitystore_client.describe_group(
            IdentityStoreId=identity_store_id,
            GroupId=group_id
        )
        sleep(0.1)
        # Get the display name, Group ID if not found
        display_name = group_response.get('DisplayName')
        if not display_name:
            logger.warning(f"No display name found for group ID {group_id}")
            return group_id

        # Store both mappings to handle lookups by either ID or name
        group_display_names[group_id] = display_name
        group_display_names[display_name] = display_name

        return display_name
    except Exception as e:
        logger.warning(f"Error getting group name for ID {group_id}: {str(e)}")
        return group_id


def get_account_assignments():
    """Get all account assignments and organize them into global and target mappings with optimized processing"""
    # Initialize required variables
    account_name_cache = {}
    global_mapping = []
    target_mapping = []
    group_display_names = {}
    accounts = []
    active_account_ids = set()
    global skip_management_perm_sets  # Use global variables

    def get_account_name(acc_id):
        account_name = next((acc['Name']
                            for acc in accounts if acc['Id'] == acc_id), None)
        if account_name:
            return account_name

        try:
            acc = organizations.describe_account(AccountId=acc_id)['Account']
            return acc['Name']
        except Exception:
            return None

    try:
        mgmt_acc = organizations.describe_account(
            AccountId=MANAGEMENT_ACCOUNT_ID)['Account']
        accounts.append(mgmt_acc)
        account_name_cache[mgmt_acc['Id']] = mgmt_acc['Name']
        if mgmt_acc['Status'] != 'SUSPENDED':
            active_account_ids.add(mgmt_acc['Id'])

        accounts_paginator = organizations.get_paginator('list_accounts')
        for page in accounts_paginator.paginate():
            sleep(0.1)
            for account in page['Accounts']:
                if account['Id'] == MANAGEMENT_ACCOUNT_ID:
                    continue
                accounts.append(account)
                account_name_cache[account['Id']] = account['Name']
                if account['Status'] != 'SUSPENDED':
                    active_account_ids.add(account['Id'])

        perm_set_cache = {}
        all_perm_sets = []
        perm_sets_response = ic_admin.list_permission_sets(
            InstanceArn=ic_instance_arn,
            MaxResults=100
        )
        all_perm_sets.extend(perm_sets_response['PermissionSets'])

        while 'NextToken' in perm_sets_response:
            perm_sets_response = ic_admin.list_permission_sets(
                InstanceArn=ic_instance_arn,
                NextToken=perm_sets_response['NextToken'],
                MaxResults=100
            )
            all_perm_sets.extend(perm_sets_response['PermissionSets'])

        for perm_set_arn in all_perm_sets:
            try:
                response = ic_admin.describe_permission_set(
                    InstanceArn=ic_instance_arn,
                    PermissionSetArn=perm_set_arn
                )
                sleep(0.1)
                perm_set_cache[perm_set_arn] = response['PermissionSet']['Name']
            except Exception as e:
                logger.error(
                    f"Error getting permission set details for {perm_set_arn}: {str(e)}")

        assignments_by_group = {}
        for perm_set_arn in all_perm_sets:
            perm_set_name = perm_set_cache.get(perm_set_arn)
            if not perm_set_name:
                continue

            logger.info(f"Processing permission set: {perm_set_name}")

            # Process all active accounts for this permission set
            for account_id in active_account_ids:
                try:
                    assignments_response = ic_admin.list_account_assignments(
                        InstanceArn=ic_instance_arn,
                        AccountId=account_id,
                        PermissionSetArn=perm_set_arn,
                        MaxResults=100
                    )
                    sleep(0.1)

                    assignments = assignments_response.get(
                        'AccountAssignments', [])
                    while 'NextToken' in assignments_response:
                        assignments_response = ic_admin.list_account_assignments(
                            InstanceArn=ic_instance_arn,
                            AccountId=account_id,
                            PermissionSetArn=perm_set_arn,
                            MaxResults=100,
                            NextToken=assignments_response['NextToken']
                        )
                        assignments.extend(assignments_response.get(
                            'AccountAssignments', []))

                    # If this is the management account and we're in delegated mode,
                    # mark this permission set to be skipped if it has any assignments
                    if IS_DELEGATED and account_id == MANAGEMENT_ACCOUNT_ID and assignments:
                        skip_management_perm_sets.add(perm_set_arn)
                        logger.info(
                            f"Marking permission set {perm_set_name} to be skipped (provisioned in management account)")
                        continue

                    for assignment in assignments:
                        if assignment['PrincipalType'] != 'GROUP':
                            continue

                        group_id = assignment['PrincipalId']
                        group_name = get_group_name(
                            group_id, identity_store_id, group_display_names)

                        if not group_name:
                            logger.warning(
                                f"Warning: Empty group name encountered")
                            continue

                        if group_name not in assignments_by_group:
                            assignments_by_group[group_name] = {}

                        # Skip if this permission set is provisioned in management account
                        if IS_DELEGATED and perm_set_arn in skip_management_perm_sets:
                            continue

                        if perm_set_name not in assignments_by_group[group_name]:
                            assignments_by_group[group_name][perm_set_name] = set(
                            )

                        assignments_by_group[group_name][perm_set_name].add(
                            account_id)
                        logger.debug(
                            f"Successfully added account {account_id} to {group_name}/{perm_set_name}")

                except Exception as e:
                    logger.error(
                        f"Error processing assignments for account {account_id}: {str(e)}")

        # Identify global vs target assignments
        seen_groups = set()

        for group_name, perm_sets_data in assignments_by_group.items():
            if group_name in seen_groups:
                continue

            display_name = group_display_names.get(group_name, group_name)
            seen_groups.add(group_name)
            seen_groups.add(display_name)

            logger.info(f"Processing assignments for group: {display_name}")
            global_perm_sets = []
            target_perm_sets = {}

            for curr_perm_set_name, assigned_accounts in perm_sets_data.items():
                # Skip if this permission set is in the skip list (management account permission sets)
                curr_perm_set_arn = next((arn for arn in all_perm_sets if perm_set_cache.get(
                    arn) == curr_perm_set_name), None)
                if curr_perm_set_arn in skip_management_perm_sets:
                    logger.info(
                        f"Skipping {curr_perm_set_name} in target mapping as it is provisioned in management account")
                    continue

                assigned_accounts_list = sorted(list(assigned_accounts))
                covered_accounts = set()
                non_management_active_accounts = []

                # Process accounts and organize them into the target structure
                logger.debug(
                    f"Processing assignments for {display_name}, perm set: {curr_perm_set_name}")
                target_list = []
                account_names = set()

                # Process all accounts directly
                for account_id in assigned_accounts_list:
                    account_name = get_account_name(account_id)
                    if account_name:
                        account_names.add(account_name)
                        covered_accounts.add(account_id)

                # Add all accounts to the target list
                if account_names:
                    target_list.append({
                        "Accounts": sorted(list(account_names))
                    })

                logger.info(
                    f"Collecting accounts for {display_name}: {curr_perm_set_name}")
                covered_accounts = set()  # Reset for this permission set
                try:
                    if MANAGEMENT_ACCOUNT_ID in active_account_ids:
                        covered_accounts.add(MANAGEMENT_ACCOUNT_ID)
                        mgmt_acc = organizations.describe_account(
                            AccountId=MANAGEMENT_ACCOUNT_ID)['Account']
                        account_names.add(mgmt_acc['Name'])
                        logger.debug(
                            f"Added management account {MANAGEMENT_ACCOUNT_ID} to covered accounts")
                except Exception as e:
                    logger.error(f"Error getting management account: {str(e)}")

                if IS_DELEGATED:
                    logger.info(
                        f"Delegated admin detected. \
                            Permission set assigned with all accounts except management account will be considered global as management account permission sets MUST be created and provisioned from the management account. \
                                Checking if {curr_perm_set_name} is global...")
                    # add all accounts to global if running in delegated admin and assigned to all accounts or all accounts except management account.
                    # all_accounts_assigned = all(
                    #     acc_id in assigned_accounts for acc_id in active_account_ids)

                    non_management_active_accounts = [
                        acc for acc in active_account_ids if acc != MANAGEMENT_ACCOUNT_ID]
                    all_non_management_assigned = sorted(
                        assigned_accounts_list) == sorted(non_management_active_accounts)

                    if all_non_management_assigned:
                        global_perm_sets.append(curr_perm_set_name)
                    elif target_list:
                        target_perm_sets[curr_perm_set_name] = target_list
                else:
                    logger.info(
                        f"Delegated admin not detected. Identity Center running in Management account \
                            Permission set assigned with all accounts including the management account will be considered global. \
                                Checking if {curr_perm_set_name} is global...")
                    # For non-delegated admin, only add to global if assigned to all accounts
                    if all(acc_id in assigned_accounts for acc_id in active_account_ids):
                        global_perm_sets.append(curr_perm_set_name)
                    elif target_list:
                        target_perm_sets[curr_perm_set_name] = target_list

        # Add mapping data
            if global_perm_sets:
                global_mapping.append({
                    "GlobalGroupName": display_name,
                    "PermissionSetName": sorted(global_perm_sets),
                    "Target": "Global"
                })

            if target_perm_sets:
                for perm_set_name, targets in target_perm_sets.items():
                    target_mapping.append({
                        "TargetGroupName": display_name,
                        "PermissionSetName": [perm_set_name],
                        "Target": targets
                    })

        return global_mapping, target_mapping

    except Exception as e:
        logger.error(f"Error in get_account_assignments: {str(e)}")
        return [], []


def create_directory_if_not_exists(path):
    """Create directory if it doesn't exist"""
    logger.info(f"Checking if directory exists: {path}")
    if not os.path.exists(path):
        os.makedirs(path)


def write_json_file(data, filepath):
    """Write data to a JSON file with proper formatting"""
    logger.info(f"Writing JSON file: {filepath}")
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)


def main():
    try:
        # Initialize global variables for delegated admin status and management account ID
        initialize_global_vars()

        base_dir = "identity-center-mapping-info"
        perm_sets_dir = os.path.join(base_dir, "permission-sets")
        create_directory_if_not_exists(perm_sets_dir)

        # get all permission sets and create individual JSON files
        perm_sets_response = ic_admin.list_permission_sets(
            InstanceArn=ic_instance_arn,
            MaxResults=100
        )
        sleep(0.1)
        all_perm_sets = perm_sets_response['PermissionSets']

        while 'NextToken' in perm_sets_response:
            perm_sets_response = ic_admin.list_permission_sets(
                InstanceArn=ic_instance_arn,
                NextToken=perm_sets_response['NextToken'],
                MaxResults=100
            )
            all_perm_sets.extend(perm_sets_response['PermissionSets'])
            sleep(0.1)

        # Get assignments first to identify management account permission sets
        # This will populate skip_management_perm_sets for permission sets provisioned in management account
        global_mapping, target_mapping = get_account_assignments()

        # Create permission set files, skipping those provisioned in management account
        for perm_set_arn in all_perm_sets:
            if not (IS_DELEGATED and perm_set_arn in skip_management_perm_sets):
                perm_set_json = get_permission_set_details(perm_set_arn)
                perm_set_file = os.path.join(
                    perm_sets_dir, f"{perm_set_json['Name']}.json")
                write_json_file(perm_set_json, perm_set_file)
                logger.info(f"Created permission set file: {perm_set_file}")

        global_mapping_file = os.path.join(base_dir, "global-mapping.json")
        write_json_file(global_mapping, global_mapping_file)
        logger.info(f"Created global mapping file: {global_mapping_file}")

        target_mapping_file = os.path.join(base_dir, "target-mapping.json")
        write_json_file(target_mapping, target_mapping_file)
        logger.info(f"Created target mapping file: {target_mapping_file}")

    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}")
        raise


if __name__ == "__main__":
    main()
