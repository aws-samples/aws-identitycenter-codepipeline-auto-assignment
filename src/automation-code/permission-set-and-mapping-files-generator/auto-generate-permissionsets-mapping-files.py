"""
This script fetches existing permission sets and assignments from AWS IAM Identity Center
and creates the corresponding JSON files in the identity-center-mapping-info directory structure.
"""

import json
import logging
import os
from time import sleep
import boto3
from botocore.config import Config
from typing import Dict, List

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
console_handler.setLevel(logging.INFO)

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
        max_attempts=5,
        mode='standard'
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


def get_group_name(group_id, identitystore_client, identity_store_id, group_display_names):
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
    """Get all account assignments and organize them into global and target mappings"""
    logger.info("Getting all account assignments")
    global_mapping = []
    target_mapping = []
    group_display_names = {}

    try:
        # Get all AWS accounts and check active account IDs
        accounts_paginator = organizations.get_paginator('list_accounts')
        accounts = []
        active_account_ids = set()
        for page in accounts_paginator.paginate():
            sleep(0.1)
            for account in page['Accounts']:
                accounts.append(account)
                if account['Status'] != "SUSPENDED":
                    active_account_ids.add(account['Id'])

        # Get all permission sets
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

        assignments_by_group = {}

        perm_set_name_map = {}
        for perm_set_arn in all_perm_sets:
            try:
                response = ic_admin.describe_permission_set(
                    InstanceArn=ic_instance_arn,
                    PermissionSetArn=perm_set_arn
                )
                sleep(0.1)
                curr_name = response['PermissionSet']['Name']
                logger.debug(
                    f"Debug: Mapping permission set ARN {perm_set_arn} to name: {curr_name}")
                perm_set_name_map[perm_set_arn] = response['PermissionSet']['Name']
            except Exception as e:
                logger.error(
                    f"Error getting permission set details for {perm_set_arn}: {str(e)}")
                continue

        for perm_set_arn in all_perm_sets:
            curr_perm_set_name = perm_set_name_map.get(perm_set_arn)
            if not curr_perm_set_name:
                logger.warning(
                    f"Warning: Permission set ARN {perm_set_arn} not found in mapping")
                continue
            logger.info(f"Processing permission set: {curr_perm_set_name}")

            # get assignments for each active account
            for account_id in active_account_ids:
                assignments_response = ic_admin.list_account_assignments(
                    InstanceArn=ic_instance_arn,
                    AccountId=account_id,
                    PermissionSetArn=perm_set_arn,
                    MaxResults=100
                )
                sleep(0.1)
                account_assignment = []
                if 'AccountAssignments' in assignments_response:
                    account_assignment = assignments_response['AccountAssignments']
                while 'NextToken' in assignments_response:
                    assignments_response = ic_admin.list_account_assignments(
                        InstanceArn=ic_instance_arn,
                        AccountId=account_id,
                        PermissionSetArn=perm_set_arn,
                        MaxResults=100,
                        NextToken=assignments_response['NextToken']
                    )
                    account_assignment.append(
                        assignments_response['AccountAssignments'])

                for assignment in account_assignment:
                    if assignment['PrincipalType'] == 'GROUP':
                        group_id = assignment['PrincipalId']

                        group_name = get_group_name(
                            group_id, identitystore_client, identity_store_id, group_display_names)

                        # get permission set name from the mapping
                        curr_perm_set_name = perm_set_name_map.get(
                            assignment['PermissionSetArn'])
                        if not curr_perm_set_name:
                            logger.warning(
                                f"Warning: Permission set ARN {assignment['PermissionSetArn']} not found in mapping")
                            continue
                        logger.debug(
                            f"Debug: Processing assignment - Group: {group_name}, Permission Set: {curr_perm_set_name}")

                        try:
                            if not group_name:
                                logger.warning(
                                    f"Warning: Empty group name encountered")
                                continue

                            if not curr_perm_set_name:
                                logger.warning(
                                    f"Warning: Empty permission set name encountered")
                                continue

                            if group_name not in assignments_by_group:
                                logger.debug(
                                    f"Debug: Creating new group entry for {group_name}")
                                assignments_by_group[group_name] = {}

                            if curr_perm_set_name not in assignments_by_group[group_name]:
                                logger.debug(
                                    f"Debug: Creating new permission set entry for {curr_perm_set_name} in group {group_name}")
                                assignments_by_group[group_name][curr_perm_set_name] = set(
                                )

                            assignments_by_group[group_name][curr_perm_set_name].add(
                                account_id)
                            logger.info(
                                f"Successfully added account {account_id} to {group_name}/{curr_perm_set_name}")

                        except Exception as e:
                            logger.error(
                                f"Error processing assignment: Group={group_name}, PermSet={curr_perm_set_name}, Account={account_id}: {str(e)}")
                            continue

        # Identify global vs target assignments
        seen_groups = set()

        for group_name, perm_sets_data in assignments_by_group.items():
            if group_name in seen_groups:
                continue

            display_name = group_display_names.get(group_name, group_name)
            seen_groups.add(group_name)
            seen_groups.add(display_name)

            global_perm_sets = []
            target_perm_sets = {}

            for curr_perm_set_name, assigned_accounts in perm_sets_data.items():
                assigned_accounts_list = sorted(list(assigned_accounts))
                active_accounts_list = sorted(list(active_account_ids))

                # Check if build is running in management account or delegated admin
                management_account_id = organizations.describe_organization()[
                    'Organization']['MasterAccountId']
                is_delegated_admin = sts_client.get_caller_identity()[
                    'Account'] != management_account_id

                if is_delegated_admin:
                    # For delegated admin, consider it global if assigned to all accounts except management
                    non_management_active_accounts = [
                        acc for acc in active_accounts_list if acc != management_account_id]
                    if sorted(assigned_accounts_list) == sorted(non_management_active_accounts):
                        global_perm_sets.append(curr_perm_set_name)
                    else:
                        target_perm_sets[curr_perm_set_name] = assigned_accounts_list
                else:
                    # For management account, must be assigned to all accounts to be global
                    if assigned_accounts_list == active_accounts_list:
                        global_perm_sets.append(curr_perm_set_name)
                    else:
                        target_perm_sets[curr_perm_set_name] = assigned_accounts_list

        # Add to global mapping if there are any global permission sets
            if global_perm_sets:
                global_mapping.append({
                    'GlobalGroupName': display_name,
                    'PermissionSetName': sorted(global_perm_sets),
                    'TargetAccountid': "Global"
                })

            # add to target mapping if there are any target permission sets
            for perm_set_name, accounts in target_perm_sets.items():
                # Group accounts by their OUs (including nested OUs)
                accounts_by_ou = {}
                individual_accounts = []
                root_id = organizations.list_roots()['Roots'][0]['Id']

                def get_all_accounts_in_ou(ou_id):
                    """Get all accounts in an OU and its child OUs"""
                    all_accounts = set()
                    # get accounts
                    paginator = organizations.get_paginator(
                        'list_accounts_for_parent')
                    for page in paginator.paginate(ParentId=ou_id):
                        for account in page['Accounts']:
                            if account['Status'] == 'ACTIVE':
                                all_accounts.add(account['Id'])
                        sleep(0.1)

                    # Get accounts from child OUs
                    paginator = organizations.get_paginator('list_children')
                    for page in paginator.paginate(ParentId=ou_id, ChildType='ORGANIZATIONAL_UNIT'):
                        for child in page['Children']:
                            all_accounts.update(
                                get_all_accounts_in_ou(child['Id']))
                        sleep(0.1)

                    return all_accounts

                def get_ou_path(account_id):
                    """Get full OU path for an account"""
                    ou_path = []
                    current_id = account_id

                    while True:
                        try:
                            parents = organizations.list_parents(
                                ChildId=current_id)
                            parent = next((p for p in parents.get('Parents', [])
                                           if p['Type'] == 'ORGANIZATIONAL_UNIT'), None)

                            if not parent:
                                break

                            ou_details = organizations.describe_organizational_unit(
                                OrganizationalUnitId=parent['Id']
                            )
                            ou_path.append({
                                'name': ou_details['OrganizationalUnit']['Name'],
                                'id': parent['Id']
                            })
                            current_id = parent['Id']
                            sleep(0.1)
                        except Exception as e:
                            logger.warning(
                                f"Error getting OU path for {current_id}: {str(e)}")
                            break

                    return ou_path

                # group accounts by their complete OU paths
                for account_id in accounts:
                    try:
                        ou_path = get_ou_path(account_id)
                        if not ou_path:
                            individual_accounts.append(account_id)
                            continue

                        # Add account to each level of its OU hierarchy
                        for i in range(len(ou_path)):
                            current_ou = ou_path[i]
                            ou_name = current_ou['name']
                            ou_id = current_ou['id']

                            if ou_name not in accounts_by_ou:
                                accounts_by_ou[ou_name] = {
                                    'id': ou_id,
                                    'accounts': set(),
                                    'depth': i,  # ou depth
                                    'parent_ou': ou_path[i-1]['name'] if i > 0 else None
                                }
                            accounts_by_ou[ou_name]['accounts'].add(account_id)

                    except Exception as e:
                        logger.warning(
                            f"Could not resolve OU path for account {account_id}: {str(e)}")
                        individual_accounts.append(account_id)
                    sleep(0.1)

                # Process accounts by OU, handling nested OUs
                target_accounts = []

                # sort OU by depth to process parent OU first
                sorted_ous = sorted(accounts_by_ou.items(),
                                    key=lambda x: x[1]['depth'])
                processed_accounts = set()

                for ou_name, ou_data in sorted_ous:
                    if ou_data['parent_ou'] and ou_data['parent_ou'] in accounts_by_ou:
                        # skip if parent OU was already processed and included all accounts
                        parent_accounts = accounts_by_ou[ou_data['parent_ou']]['accounts']
                        if ou_data['accounts'].issubset(parent_accounts):
                            continue

                    try:
                        # get all accounts in this OU (including nested OUs)
                        all_ou_accounts = get_all_accounts_in_ou(ou_data['id'])
                        assigned_accounts = ou_data['accounts'] - \
                            processed_accounts

                        if not assigned_accounts:
                            continue
                        # get accounts by ou
                        # Only use OU name if all accounts in the OU AND all its child OUs have the permission set assigned
                        is_valid_ou = (assigned_accounts == all_ou_accounts and
                                       len(assigned_accounts) == len(all_ou_accounts) and
                                       len(assigned_accounts) > 0 and
                                       validate_target_accounts(list(assigned_accounts), accounts_by_ou, logger))

                        if is_valid_ou:
                            logger.info(
                                f"Validated all accounts in OU {ou_name} have permission set assigned")
                            target_accounts.append(f"ou:{ou_name}")
                            processed_accounts.update(assigned_accounts)
                        else:
                            # get accounts by name or Id if failed to get name
                            for account_id in assigned_accounts:
                                try:
                                    account_details = organizations.describe_account(
                                        AccountId=account_id)
                                    if account_details['Account']['Name']:
                                        target_accounts.append(
                                            f"name:{account_details['Account']['Name']}")
                                    else:
                                        target_accounts.append(account_id)
                                    processed_accounts.add(account_id)
                                except Exception as e:
                                    logger.warning(
                                        f"Could not get account name for {account_id}: {str(e)}")
                                    target_accounts.append(account_id)
                                    processed_accounts.add(account_id)
                                sleep(0.1)
                    except Exception as e:
                        logger.warning(
                            f"Error processing OU {ou_name}: {str(e)}")
                        # get accounts by id
                        for account_id in ou_data['accounts']:
                            target_accounts.append(account_id)

                # get remaining accounts
                for account_id in individual_accounts:
                    try:
                        account_details = organizations.describe_account(
                            AccountId=account_id)
                        if account_details['Account']['Name']:
                            target_accounts.append(
                                f"name:{account_details['Account']['Name']}")
                        else:
                            target_accounts.append(account_id)
                    except Exception as e:
                        logger.warning(
                            f"Could not get account name for {account_id}: {str(e)}")
                        target_accounts.append(account_id)
                    sleep(0.1)

                target_mapping.append({
                    'TargetGroupName': display_name,
                    'PermissionSetName': [perm_set_name],
                    'TargetAccountid': target_accounts
                })

        return global_mapping, target_mapping

    except Exception as e:
        logger.error(f"Error getting account assignments: {str(e)}")
        raise


def create_directory_if_not_exists(path):
    """Create directory if it doesn't exist"""
    logger.info(f"Checking if directory exists: {path}")
    if not os.path.exists(path):
        os.makedirs(path)


def validate_target_accounts(accounts: List[str], ou_data: Dict, logger=None) -> bool:
    """
    Validate that all accounts in a target group are properly assigned.
    This is critical for OU-based assignments to ensure we don't accidentally
    grant permissions to accounts that shouldn't have them.
    """
    """Validate if all accounts in an OU structure have the permission set assigned"""
    if not accounts:
        return False

    all_accounts = set()
    for ou_info in ou_data.values():
        all_accounts.update(ou_info['accounts'])

    return all_accounts.issubset(set(accounts))


def write_json_file(data, filepath):
    """Write data to a JSON file with proper formatting"""
    logger.info(f"Writing JSON file: {filepath}")
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)


def main():

    try:
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

        for perm_set_arn in all_perm_sets:
            perm_set_json = get_permission_set_details(perm_set_arn)
            perm_set_file = os.path.join(
                perm_sets_dir, f"{perm_set_json['Name']}.json")
            write_json_file(perm_set_json, perm_set_file)
            logger.info(f"Created permission set file: {perm_set_file}")

        # get assignments and create mapping files
        global_mapping, target_mapping = get_account_assignments()

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
