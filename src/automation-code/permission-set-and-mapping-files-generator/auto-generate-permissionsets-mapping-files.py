"""
This script fetches existing permission sets and assignments from AWS IAM Identity Center
and creates the corresponding JSON files in the identity-center-mapping-info directory structure.
"""

import os
import json
import boto3
import logging
from time import sleep
from botocore.exceptions import ClientError


logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Stream handler to print logs on screen
console_handler= logging.StreamHandler()
console_handler.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

runtime_region = os.getenv('AWS_REGION')
ic_admin = boto3.client('sso-admin', runtime_region)
identitystore_client = boto3.client('identitystore', runtime_region)
organizations = boto3.client('organizations')
ic_instance_arn = os.getenv('IC_INSTANCE_ARN')
identity_store_id = os.getenv('IDENTITY_STORE_ID')

def get_permission_set_details(perm_set_arn):
    """Get detailed information about a permission set including policies and tags"""
    try:
        describe_perm_set = ic_admin.describe_permission_set(
            InstanceArn=ic_instance_arn,
            PermissionSetArn=perm_set_arn
        )
        perm_set = describe_perm_set['PermissionSet']
        sleep(0.1)
        
        managed_policies = []
    
        paginator = ic_admin.get_paginator('list_managed_policies_in_permission_set')
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

        # Get inline policy if it exists
        try:
            inline_policy = ic_admin.get_inline_policy_for_permission_set(
                InstanceArn=ic_instance_arn,
                PermissionSetArn=perm_set_arn
            ).get('InlinePolicy', None)
            sleep(0.1)  # Avoid hitting API limit
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
            "InlinePolicies": json.loads(inline_policy) if inline_policy else []
        }
        
        return perm_set_json
    
    except Exception as e:
        logger.error(f"Error getting permission set details for {perm_set_arn}: {str(e)}")
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
        
        # Get the display name, fallback to ID if not found
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
    global_mapping = []
    target_mapping = []
    group_display_names = {}
    
    try:
        # Get all AWS accounts and create a set of active account IDs
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
                logger.debug(f"Debug: Mapping permission set ARN {perm_set_arn} to name: {curr_name}")
                perm_set_name_map[perm_set_arn] = response['PermissionSet']['Name']
            except Exception as e:
                logger.error(f"Error getting permission set details for {perm_set_arn}: {str(e)}")
                continue
        
        for perm_set_arn in all_perm_sets:
            curr_perm_set_name = perm_set_name_map.get(perm_set_arn)
            if not curr_perm_set_name:
                logger.warning(f"Warning: Permission set ARN {perm_set_arn} not found in mapping")
                continue
            logger.info(f"Processing permission set: {curr_perm_set_name}")
            
            # Get assignments for each active account
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
                # account_assignment = assignments_response['AccountAssignments']
                while 'NextToken' in assignments_response:
                    assignments_response = ic_admin.list_account_assignments(
                        InstanceArn=ic_instance_arn,
                        AccountId=account_id,
                        PermissionSetArn=perm_set_arn,
                        MaxResults=100,
                        NextToken=assignments_response['NextToken']
                    )
                    account_assignment.append(assignments_response['AccountAssignments'])

                
                for assignment in account_assignment:
                    if assignment['PrincipalType'] == 'GROUP':
                        group_id = assignment['PrincipalId']

                        group_name = get_group_name(group_id, identitystore_client, identity_store_id, group_display_names)
                        
                        # Get permission set name from the mapping
                        curr_perm_set_name = perm_set_name_map.get(assignment['PermissionSetArn'])
                        if not curr_perm_set_name:
                            logger.warning(f"Warning: Permission set ARN {assignment['PermissionSetArn']} not found in mapping")
                            continue
                        logger.debug(f"Debug: Processing assignment - Group: {group_name}, Permission Set: {curr_perm_set_name}")
                        
                        try:
                            if not group_name:
                                logger.warning(f"Warning: Empty group name encountered")
                                continue
                                
                            if not curr_perm_set_name:
                                logger.warning(f"Warning: Empty permission set name encountered")
                                continue
                            
                            if group_name not in assignments_by_group:
                                logger.debug(f"Debug: Creating new group entry for {group_name}")
                                assignments_by_group[group_name] = {}
                                
                            if curr_perm_set_name not in assignments_by_group[group_name]:
                                logger.debug(f"Debug: Creating new permission set entry for {curr_perm_set_name} in group {group_name}")
                                assignments_by_group[group_name][curr_perm_set_name] = set()
                            
                            assignments_by_group[group_name][curr_perm_set_name].add(account_id)
                            logger.info(f"Successfully added account {account_id} to {group_name}/{curr_perm_set_name}")
                            
                        except Exception as e:
                            logger.error(f"Error processing assignment: Group={group_name}, PermSet={curr_perm_set_name}, Account={account_id}: {str(e)}")
                            continue
        
        # Identify global vs target assignments
        # global_groups = set()
        # target_groups = set()
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
                
                # Check if this permission set is global?
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
            
            # Add to target mapping if there are any target permission sets
            for perm_set_name, accounts in target_perm_sets.items():
                target_mapping.append({
                    'TargetGroupName': display_name,
                    'PermissionSetName': [perm_set_name],
                    'TargetAccountid': accounts
                })
        
        return global_mapping, target_mapping
    
    except Exception as e:
        logger.error(f"Error getting account assignments: {str(e)}")
        raise

def create_directory_if_not_exists(path):
    """Create directory if it doesn't exist"""
    if not os.path.exists(path):
        os.makedirs(path)

def write_json_file(data, filepath):
    """Write data to a JSON file with proper formatting"""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)

def main():
    try:
        base_dir = "identity-center-mapping-info"
        perm_sets_dir = os.path.join(base_dir, "permission-sets")
        create_directory_if_not_exists(perm_sets_dir)
        
        # Get all permission sets and create individual JSON files
        perm_sets_response = ic_admin.list_permission_sets(
            InstanceArn=ic_instance_arn,
            MaxResults=100
        )
        all_perm_sets = perm_sets_response['PermissionSets']
        
        while 'NextToken' in perm_sets_response:
            perm_sets_response = ic_admin.list_permission_sets(
                InstanceArn=ic_instance_arn,
                NextToken=perm_sets_response['NextToken'],
                MaxResults=100
            )
            all_perm_sets.extend(perm_sets_response['PermissionSets'])
        
        for perm_set_arn in all_perm_sets:
            perm_set_json = get_permission_set_details(perm_set_arn)
            perm_set_file = os.path.join(perm_sets_dir, f"{perm_set_json['Name']}.json")
            write_json_file(perm_set_json, perm_set_file)
            logger.info(f"Created permission set file: {perm_set_file}")
        
        # Get assignments and create mapping files
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