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

## 3.0.0

### Major Architectural Changes
   - Replaced Lambda functions with CodeBuild projects for core automation:
      - Migrated auto-permissionsets.py and auto-assignment.py from Lambda to CodeBuild.
      - This change allows for longer execution times (no timeout issues), more memory, and easier dependency management.
   - Implemented CodePipeline V2:
      - Updated codepipeline-stack.template to use the latest CodePipeline features.
   - Added support for CodeStar connections:
      - Allows integration with various source control providers beyond AWS CodeCommit.
      - Updated codepipeline-stack.template to include CodeStar connection options.
   - Enhanced S3 bucket management:
      - Implemented versioning for S3 objects to ensure data integrity and allow rollbacks.
      - Added option to create a new KMS key for S3 bucket encryption or use an existing key.

### New Features
   - Syntax validation for permission sets and mapping files:
      - Added syntax-validator.py to perform comprehensive checks on JSON structures.
      - Validates permission set names, ARNs, policy structures, and mapping file format and content.
   - Generation of permission sets and mapping files:
      - New feature to generate JSON files from existing Identity Center configuration.
      - Added auto-generate-permissionsets-mapping-files.py to facilitate this process.
      - Added EventBridge rule to automatically trigger CodeBuild project when auto-generate-permissionsets-mapping-files.py is uploaded to S3, for JSON identity-center-mapping-info files generation.
   - Support for account names and OU names in target mappings:
      - Enhanced auto-assignment.py to resolve account names and OUs, including nested OUs, in addition to using just account IDs.
      - Allows more human-readable and flexible target specifications in mapping files.
   - Support for permission boundaries:
      - Added ability to define and manage permission boundaries for permission sets, using both AWS Managed and Customer Managed Policies.
   - Scheduled baselining of Identity Center configuration:
      - Added EventBridge rule to periodically (Every 12 hours) trigger the automation process.
      - Helps maintain desired state even if manual changes are made outside the pipeline.
   - Improved event-driven triggers:
      - Updated EventBridge rules to trigger on successful account creation and invitation acceptance.
      - More precise and efficient handling of organizational changes.
   - Moved CloudFormation templates to a dedicated templates directory for better organization.

### Enhancements
   - Error handling and logging improvements:
      - Implemented more granular error catching and reporting across all scripts.
      - Added detailed logging for better traceability and debugging.
      - Enhanced logging with CloudWatch integration into CodeBuild project for better traceability.
   - Optimized API calls:
      - Implemented batching and pagination for certain AWS API calls to reduce the risk of throttling.
   - Handling of suspended accounts and accounts pending closure:
      - Updated account processing logic to skip accounts in these states.
      - Prevents unnecessary operations on inactive accounts.
   - Improved account assignment process:
      - Enhanced logic for detecting and handling changes in account assignments.
      - Implemented more efficient provisioning and deprovisioning of permission sets.
   - Expanded Organizations integration:
      - Added support for retrieving and working with nested organizational units.
   - IAM permission refinements:
      - Implemented least privilege principle more strictly across all IAM roles.
      - Updated IAM policies in codepipeline-stack.template, identity-center-automation.template, and identity-center-s3-bucket.template.
      - Updated IAM roles with more granular permissions for CodeBuild, EventBridge, and other AWS services.
   - Dependency updates:
      - Upgraded boto3 and other Python dependencies to latest compatible versions.
   - Improved handling of Control Tower managed permission sets:
      - Enhanced logic to identify and preserve Control Tower managed resources.
      - Updated skipping mechanism for these permission sets to prevent unintended modifications.
   - Performance optimizations:
      - Implemented batching for certain AWS API calls to reduce the risk of throttling.
      - Optimized loops and data structures for better efficiency in large-scale environments.
   - Compatibility checks:
      - Added checks to ensure backward compatibility with existing deployment structures where possible.
      - Provided migration guidance for users upgrading from previous versions.

### Bug Fixes
   - Fixed issues with whitespace handling in permission set and group names.
   - Corrected validation logic for various fields in permission sets and mapping files.
   - Addressed potential race conditions in account assignment operations.
   - Fixed the timeout issue in automation. 

### File and Template Updates
   - codepipeline-stack.template:
      - Added parameters for CodeStar connections and source control options.
      - Updated IAM roles and policies for CodeBuild projects with more granular access.
      - Implemented new stages for syntax validation.
      - Added a standalone CodeBuild Project for JSON files generation.
      - Added EventBridge configuration for S3 bucket.
      - Created new EventBridge rule to trigger CodeBuild project for auto-generation of mapping files.
      - Added new IAM role for EventBridge to start CodeBuild projects.
   - identity-center-automation.template:
      - Removed Lambda resources and added CodeBuild project configurations.
      - Updated EventBridge rules to trigger CodeBuild projects instead of Lambda functions.
      - Added new parameters for CodeBuild project names and artifact bucket.
      - Updated IAM permissions to include new SSO and Organizations actions.
      - Added support for new SSO API calls related to permission boundaries and account assignments.
   - identity-center-s3-bucket.template:
      - Added options for KMS key creation and management.
      - Updated bucket policies to reflect new versioning requirements.
   - buildspec files:
      - Created new buildspec files for syntax validation, permission set creation, and assignment processes.
      - Updated existing buildspecs to align with new CodeBuild project structure.
   - Python scripts:
      - Significant updates to auto-permissionsets.py and auto-assignment.py to work in CodeBuild environment.
      - Updated logging statements in all python scrips for better visibility.
      - Added new validation functions and improved error handling.
      - Implemented logic to handle account names and OU names in target mappings.

### Documentation Updates
   - Updated README.md:
      - Revised architecture diagram to reflect new components and workflows.
      - Updated implementation instructions for both management account and delegated administrator scenarios.
      - Added sections explaining new features like syntax validation and file generation.
      - Added more detailed implementation instructions and examples.
      - Added new sections explaining new features like auto-generation of files and OU-based assignments.
      - Improved explanation of permission set, global, and target mapping structure and supported fields, with examples.
   - Updated example JSON files:
      - Revised permission set and mapping file examples to showcase new capabilities.
      - Added examples demonstrating the use of account names and OU names in target mappings, as wel as permission boundaries in permission set files.
