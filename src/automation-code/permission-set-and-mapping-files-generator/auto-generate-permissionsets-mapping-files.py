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
        # sleep(0.1)  # Avoid hitting API limit
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
        
        # Create permission set JSON structure
        perm_set_json = {
            "Name": perm_set['Name'],
            "Description": perm_set.get('Description', perm_set['Name']),
            "Session_Duration": perm_set.get('SessionDuration', 'PT1H'),
            # "Tags": tags_response.get('Tags', []),
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
    # First check if we already have this ID mapped
    if group_id in group_display_names:
        return group_display_names[group_id]
        
    try:
        # Get group details from Identity Store
        group_response = identitystore_client.describe_group(
            IdentityStoreId=identity_store_id,
            GroupId=group_id
        )
        sleep(0.1)  # Avoid hitting API limit
        
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
    group_display_names = {}  # Cache for group display names
    
    try:
        # Get all AWS accounts and create a set of active account IDs
        accounts_paginator = organizations.get_paginator('list_accounts')
        accounts = []
        active_account_ids = set()  # Use set from the beginning
        for page in accounts_paginator.paginate():
            sleep(0.1)  # Avoid hitting API limit
            for account in page['Accounts']:
                accounts.append(account)
                if account['Status'] != "SUSPENDED":
                    active_account_ids.add(account['Id'])  # Add directly to set
        
        # Get all permission sets
        perm_sets_response = ic_admin.list_permission_sets(
            InstanceArn=ic_instance_arn,
            MaxResults=100
        )
        sleep(0.1)  # Avoid hitting API limit
        all_perm_sets = perm_sets_response['PermissionSets']

        while 'NextToken' in perm_sets_response:
            perm_sets_response = ic_admin.list_permission_sets(
                InstanceArn=ic_instance_arn,
                NextToken=perm_sets_response['NextToken'],
                MaxResults=100
            )
            all_perm_sets.extend(perm_sets_response['PermissionSets'])
        
        # Track assignments and their accounts
        assignments_by_group = {}
        
        # for perm_set_arn in all_perm_sets:
        #     perm_set_name = ic_admin.describe_permission_set(
        #         InstanceArn=ic_instance_arn,
        #         PermissionSetArn=perm_set_arn
        #     )['PermissionSet']['Name']
        #     sleep(0.1)  # Avoid hitting API limit
                # Create mapping of permission set ARNs to names
        perm_set_name_map = {}
        for perm_set_arn in all_perm_sets:
            try:
                response = ic_admin.describe_permission_set(
                    InstanceArn=ic_instance_arn,
                    PermissionSetArn=perm_set_arn
                )
                sleep(0.1)
                curr_name = response['PermissionSet']['Name']
                print(f"Debug: Mapping permission set ARN {perm_set_arn} to name: {curr_name}")
                perm_set_name_map[perm_set_arn] = response['PermissionSet']['Name']
            except Exception as e:
                print(f"Error getting permission set details for {perm_set_arn}: {str(e)}")
                continue
        
        for perm_set_arn in all_perm_sets:
            curr_perm_set_name = perm_set_name_map.get(perm_set_arn)
            if not curr_perm_set_name:
                print(f"Warning: Permission set ARN {perm_set_arn} not found in mapping")
                continue
            print(f"Processing permission set: {curr_perm_set_name}")  # Debug log
            
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
                        # Get group name from cache or Identity Store
                        group_name = get_group_name(group_id, identitystore_client, identity_store_id, group_display_names)
                        
                        # Get permission set name from the mapping
                        curr_perm_set_name = perm_set_name_map.get(assignment['PermissionSetArn'])
                        if not curr_perm_set_name:
                            print(f"Warning: Permission set ARN {assignment['PermissionSetArn']} not found in mapping")
                            continue
                        # Debug logging
                        print(f"Debug: Processing assignment - Group: {group_name}, Permission Set: {curr_perm_set_name}")
                        
                        # Initialize nested dictionary structure with validation
                        try:
                            if not group_name:
                                print(f"Warning: Empty group name encountered")
                                continue
                                
                            if not curr_perm_set_name:
                                print(f"Warning: Empty permission set name encountered")
                                continue
                            
                            if group_name not in assignments_by_group:
                                print(f"Debug: Creating new group entry for {group_name}")
                                assignments_by_group[group_name] = {}
                                
                            if curr_perm_set_name not in assignments_by_group[group_name]:
                                print(f"Debug: Creating new permission set entry for {curr_perm_set_name} in group {group_name}")
                                assignments_by_group[group_name][curr_perm_set_name] = set()
                            
                            # Add account to the set for this group and permission set
                            assignments_by_group[group_name][curr_perm_set_name].add(account_id)
                            print(f"Debug: Successfully added account {account_id} to {group_name}/{curr_perm_set_name}")
                            
                        except Exception as e:
                            print(f"Error processing assignment: Group={group_name}, PermSet={curr_perm_set_name}, Account={account_id}: {str(e)}")
                            continue
                        # Initialize group in mappings if not exists
                        # if group_name not in assignments_by_group:
                        #     assignments_by_group[group_name] = {}
                        # if curr_perm_set_name not in assignments_by_group[group_name]:
                        #     assignments_by_group[group_name][curr_perm_set_name] = set()
                        #     #     'PermissionSetName': set(),  # Use set for permission sets
                        #     #     'TargetAccountid': set()  # Use set for accounts
                        #     # }
                        
                        # # Add permission set and account using sets
                        # # assignments_by_group[group_name]['PermissionSetName'].add(perm_set_name)
                        # # assignments_by_group[group_name]['TargetAccountid'].add(account_id)
                        # assignments_by_group[group_name][perm_set_name].add(account_id)
        
        # First pass: Identify global vs target assignments
        global_groups = set()
        target_groups = set()
        seen_groups = set()
        
        # for group_name, group_data in assignments_by_group.items():
        #     if group_name in seen_groups:
        #         continue

        for group_name, perm_sets_data in assignments_by_group.items():
            if group_name in seen_groups:
                continue
                
            # Get the proper display name
            display_name = group_display_names.get(group_name, group_name)
            seen_groups.add(group_name)
            seen_groups.add(display_name)
            
            # Track global and target permission sets separately for each group
            global_perm_sets = []
            target_perm_sets = {}
            
            for curr_perm_set_name, assigned_accounts in perm_sets_data.items():
                # # Convert to sorted lists for comparison
                # assigned_accounts = sorted(list(group_data['TargetAccountid']))
                # active_accounts = sorted(list(active_account_ids))
                
                # # Check if this is a global assignment (exact match of account lists)
                # if assigned_accounts == active_accounts:
                #     global_groups.add(display_name)
                # else:
                #     target_groups.add(display_name)

                # Convert to sorted lists for comparison
                assigned_accounts_list = sorted(list(assigned_accounts))
                active_accounts_list = sorted(list(active_account_ids))
                
                # Check if this permission set is global (assigned to all accounts)
                if assigned_accounts_list == active_accounts_list:
                    global_perm_sets.append(curr_perm_set_name)
                else:
                    target_perm_sets[curr_perm_set_name] = assigned_accounts_list
        
        # # Second pass: Create the mappings
        # for group_name, group_data in assignments_by_group.items():
        #     # Get the proper display name
        #     display_name = group_display_names.get(group_name, group_name)
            
        #     # Skip if we've processed this group already (by either name or ID)
        #     if display_name in global_groups:
        #         # Add to global mapping
        #         global_mapping.append({
        #             'GlobalGroupName': display_name,
        #             'PermissionSetName': sorted(list(group_data['PermissionSetName'])),
        #             'TargetAccountid': "Global"
        #         })
        #     elif display_name in target_groups:
        #         # Add to target mapping
        #         target_mapping.append({
        #             'TargetGroupName': display_name,
        #             'PermissionSetName': sorted(list(group_data['PermissionSetName'])),
        #             'TargetAccountid': sorted(list(group_data['TargetAccountid']))
        #         })
        
        # return global_mapping, target_mapping

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

# def convert_sets_to_lists(obj):
#     if isinstance(obj, dict):
#         return {key: convert_sets_to_lists(value) for key, value in obj.items()}
#     elif isinstance(obj, list):
#         return [convert_sets_to_lists(element) for element in obj]
#     elif isinstance(obj, set):
#         return sorted(list(obj))
#     else:
#         return obj

def write_json_file(data, filepath):
    """Write data to a JSON file with proper formatting"""
    # converted_data = convert_sets_to_lists(data)
    with open(filepath, 'w') as f:
        # json.dump(converted_data, f, indent=4, default=list)
        json.dump(data, f, indent=4)

def main():
    try:
        # Create base directory
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
        
        # Write global mapping file
        global_mapping_file = os.path.join(base_dir, "global-mapping.json")
        write_json_file(global_mapping, global_mapping_file)
        logger.info(f"Created global mapping file: {global_mapping_file}")
        
        # Write target mapping file
        target_mapping_file = os.path.join(base_dir, "target-mapping.json")
        write_json_file(target_mapping, target_mapping_file)
        logger.info(f"Created target mapping file: {target_mapping_file}")
        
    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}")
        raise

if __name__ == "__main__":
    main()