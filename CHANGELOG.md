# CHANGELOG

## 1.0.0
   -  initial push.

## 1.1.0
   - Updated auto-permissionsets.py file to support customer managed policy in permission set.
      - Updated the permission set example 5-example-sec-readonly.json.
   - Updated auto-permissionsets.py and identity-center-automation.template to support custom permission set session duration.
      - Default session duration is set to 1 hour.
      - Updated the permission set example 1-example-admin.json.

## 2.0.0
   - Updated identity-center-stacks-parameters.json to get additional parameters from users to support delegated administration for Identity Center and AWS Control Tower enabled accounts.
      - Check if admin is delegated for IAM Identity Center.
      - Check if AWS Control Tower is enabled.
      - Check if administrative IAM user or role for Identity Center exists in account or to deploy a new IAM role.
      - Check if administrative IAM user or role for KMS exists in account or to deploy a new IAM role.
   - Updated codepipeline-stack.template to support delegated administration for Identity Center and AWS Control Tower enabled accounts.
      - Updated S3 bucket name to make it a unique identifier.
      - Added permissions to CodeBuild IAM role to create, update and delete DynamoDB table.
      - Updated CodePipeline pipeline name from Identity-Center-Automation-Sample-Solution to Identity-Center-Automation-Solution.
   - Added IC-Delegate-Admin.yml to allow delegating  administration for IAM Identity Center to a Organization member account.
   - Updated architecture_diagram.png to reflect new features in the architecture diagram.
   - Updated identity-center-automation.template to support delegated administration for Identity Center and AWS Control Tower enabled accounts.
      - Added additional parameters to support management account and Control Tower provisioned permission sets and assignments.
      - Added DynamoDB table to store skipped permission set names and ARNs, if necessary.
      - Added additional environment variables to Lambda functions auto-permissionsets and auto-assignment.
      - Added permissions to add, remove and batch update skipped permission set names and ARNs to the DynamoDB table
      - Added permissions to Lambda execution IAM role to get the list of accounts for a provisioned Permission Set to support delegated admin and Control Tower enabled feature.
   - Updated identity-center-s3-bucket.template to support delegated administration for Identity Center and AWS Control Tower enabled accounts.
      - Added additional parameters and corresponding conditions to check if Identity Center and KMS administrator role or user exists in the account, if not, added an option to create as a part of the stack.
      - Updated S3 bucket and KMS key policy to include the appropriate admin IAM roles as principals.
      - Exported outputs to be imported by the identity-center-automation.template if new IAM roles are created.
   - Updated buildspec-param.yml to support delegated administration for Identity Center and AWS Control Tower enabled accounts.
      - Updated commands to pass the additional parameters to the corresponding CloudFormation stacks.
   - Updated auto-assignment.py to support delegated administration for Identity Center and AWS Control Tower enabled accounts.
      - Added code to skip Permission Sets provisioned in management account if Control Tower is enabled or if a Organization member account is delegated as an administrator for Identity Center. 
      - Added code to skip permission sets tagged with tag key ManagedBy and value ControlTower in order to prevent the automation from removing Permission Sets created by Control Tower.
   - Updated auto-permissionsets.py to support delegated administration for Identity Center and AWS Control Tower enabled accounts.
      - Added code to skip Permission Sets provisioned in management account if Control Tower is enabled or if a Organization member account is delegated as an administrator for Identity Center. 
      - Added code to add skipped permission set names and ARNs the DynamoDB table visibility and auditing.
      - Added code to skip permission sets tagged with tag key ManagedBy and value ControlTower in order to prevent the automation from removing Permission Sets created by Control Tower and add permission set names and ARNs to IC-SkippedPermissionSets for visibility and auditing.
      - Updated code to sync skipped permission sets with DynamoDB table to ensure items in the table are not in drift
      - Updated code to handle existing Permission Sets without description.
      - Updated code to remove drift when triggered by EventBridge rule on detecting manual changes to Identity Center

## 2.0.1
   - Updated the IAM, KMS, and S3 permissions in the codepipeline-stack.template, identity-center-automation.template, and identity-center-s3-bucket.template to fix cfn_scan failures.
   - Updated buildspec-param.yml to add CFN linting and secure checks using [cfn_nag_scan](https://github.com/stelligent/cfn_nag).
      - The CodeBuild task will fail if cfn_nag_scan detects any failure in the CloudFormation templates.

## 2.1.0
   - Bug fix: Pipeline failed with 'Parameter validation failed: Missing required parameter in input: "InstanceArn"' in cases where more than the response returned more than 100 items and needed to be iterated through.
      - Added the missing InstanceArn=ic_instance_arn to allow proper functioning of list_accounts_for_provisioned_permission_set API. 
   - Bug fix: any updates to the Lambda source code did not update the Lambda function code upon successful pipeline execution.
      - Updated the buildspec to add tags to the lambda zip file objects in S3 and obtain object versions. The versions are now referenced in the Lambda cofiguration to allow subsequent updates to lambda package code. 
   - Updated the list_groups API to get_group_id API and removed the use of depricated filter method to obtain group Id by name in the auto-assignment.py.
      - list_groups returns a paginated list of complete Group objects. Filtering for a Group by the DisplayName attribute is deprecated. Instead, GetGroupId API action will be used to obtain group Id by name.
   - Updated the Lambda runtime to the latest python3.12.
   - Updated SNS subscription protocol to email in the identity-center-automation.template
      - Email as compared to email-json allowed adding formatting to the message within ic-alert-SNSnotification lambda function to send formatted and prettier JSON message. This improves readability of the Identity Center manual modification alerts. 
   - Updated the Identity Center automation pipeline in the codepipeline-stack.template to event-driven pipeline.
      - It is recommended to use event-based change detection for pipelines as opposed to polling for changes.
   - Updated pipeline stage names to better reflect their purpose.