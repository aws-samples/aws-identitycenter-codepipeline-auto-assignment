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