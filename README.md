# CICD to Automate IAM Identity Center Permission sets Mapping and Assignments for AWS Organizations

## Background Information

AWS IAM Identity Center (successor to AWS Single Sign-On) provides account assignment APIs and AWS CloudFormation support to automate access across AWS Organizations accounts. With those available APIs, this solution allows all access provided via the IAM Identity Center services to be automated via API / CloudFormation templates, and managed as code converting all currently manual activities.

AWS IAM Identity Center requires the [AWS Organizations service](https://console.aws.amazon.com/organizations) enabled in your AWS account.

## What this solution is
 - Use AWS CodeCommit or another git repository to securely source control your own IAM Identity Center code repository. Utilize CodePipeline to create and update CloudFormation stacks of IAM Identity Center and other AWS services.
    - The AWS CodePipeline will first deploy CloudFormation stacks to create a security S3 bucket, automation Codebuild Projects and other AWS resources.
    - Optional: This solution also allows you to generate permission set and mapping JSON files by reading your existing AWS IAM Identity Center configuration.
    - Once the CloudFormation stack is completed, CodePipeline syncs all the mapping files to a Secure S3 bucket
    - Pipeline invokes the CodeBuild Project to create IAM Identity Center resources by referring the JSON files in the s3 bucket and your repository.
    - Pipeline sends you approval emails to Reject or Approve changes to Identity Center.
    - Amazon EventBridge triggers email notifications via Amazon Simple Notification Service (SNS) on manual changes to Identity Center or in case of account changes in AWS Organizations and invokes CodeBuild Project to remove manual changes and revert back to baseline configuration.
- **This solution works with both Control Tower and non Control Tower based landing zones.**

## Solution Implementation Instructions

## Prerequisite
1. AWS Organizations and IAM Identity Center are enabled.
2. [S3 Data event](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html) is enabled for IAM Identity Center source S3 bucket in account's CloudTrail service.
    - Because this solution uses AWS S3 Object-level API to trigger the CodeBuild automation and those Data events are enabled by default. [Additional charges apply](https://aws.amazon.com/cloudtrail/pricing/)

### Implementation
This solution can be implemented in Organization Management account or a delegated administrator (recommended) acount for Identity Center. It is recommended to delegate administrator for Identity Center to a separate member account dedicated for identity and access management to reduce exposure to management account and for better control over account access. Follow the appropriate instructions below depending on where you configure Identity Center, Organization Management account or a member account delegated as an administrator for Identity Center.

### Consideration

**Important note if you have AWS Control Tower enabled**
If your AWS IAM Identity Center user account is disabled, you'll get an error message when trying to provision new accounts in Account Factory. You can re-enable your IAM Identity Center user in the IAM Identity Center console.

AWS Control Tower also offers preconfigured groups to organize users that perform specific tasks in your accounts. AWS Control Tower creates these groups and assigns pre-configured permission sets to these groups and provisions them in the Organization Management account. You can also [view the list of groups and corresponding permission sets](https://docs.aws.amazon.com/controltower/latest/userguide/sso.html#sso-groups). You can choose to disable this setting in Control Tower when deploying or modifying Landing Zone, by selecting "Self-managed AWS account access with IAM Identity Center or another method" or "AWS Control Tower sets up AWS account access with IAM Identity Center" under "AWS account access configuration".

**AWS Control Tower requires these permission sets to exist for account creation and provisioning purposes**. If you chose "AWS Control Tower sets up AWS account access with IAM Identity Center" above, and to ensure that this solution does not de-provision or delete the Control Tower permission sets, you **must tag AWS Control Tower created permission sets** with ``"key:ManagedBy"`` and ``"value:ControlTower"`` before deploying the solution. Additionally, update the value of *"ControlTowerEnabled"* to "true" as mentioned in the implementation steps below.

**Navigate to the appropriate implementation steps below depending on your choice of deployment in the Management account or a delegated admin account for AWS IAM Identity Center**

### How to implement this solution in member account delegated administrator for Identity Center (Recommended):

### Consideration
Delegated administration provides a convenient way for assigned users in a registered member account to perform most IAM Identity Center administrative tasks. When you enable IAM Identity Center, your IAM Identity Center instance is created in the management account in AWS Organizations by default. This was originally designed this way so that IAM Identity Center can provision, de-provision, and update roles across all your organization's member accounts. Even though your IAM Identity Center instance must always reside in the management account, you can choose to delegate administration of IAM Identity Center to a member account in AWS Organizations, thereby extending the ability to manage IAM Identity Center from outside the management account. For more details, visit https://docs.aws.amazon.com/singlesignon/latest/userguide/delegated-admin.html#delegated-admin-tasks-member-account

Enabling delegated administration provides the following benefits:
    - Minimizes the number of people who require access to the management account to help reduce exposure and mitigate security concerns
    - Allows select administrators to assign users and groups to applications and to your organization's member accounts
    - Disallow delegated administrator for Identity Center from making changed to permissions provisioned for management account, following the zero trust principles.

**Delegated administrator cannot manage permission sets provisioned in the management account**
This is by design to prevent delegated administrator from adding/updating/removing permissions to the management account, which is considered to be the account with the most elevated permissions and should have the least exposure. 

This solution works around this by skipping the permission sets provisioned in the management account and storing a list of skipped permission sets in a DynamoDB table "IC-SkippedPermissionSets". This is also true for Control Tower based landing zones.

As delegated admin is not allowed to manage permission sets provisioned in management account or assign a permission set to the management account, you must manually create a permission set in the management account, to use just for the management account. For more details, view [best practices for delegated administrator for Identity Center](https://docs.aws.amazon.com/singlesignon/latest/userguide/delegated-admin.html#delegated-admin-best-practices).

This also recommended as a best practice:
>Create permission sets for use only in the management account – This makes it easier to administer permission sets tailored just for users accessing your management account and helps to differentiate them from permission sets managed by your delegated administrator account.

**If you have already delegated an AWS account as administrator for Identity Center, follow the steps listed under *Deployment in delegated administrator account* section below. If you have not delegated an AWS account as administrator for Identity Center yet, perform the following steps to delegate a member account as an administrator for Identity Center:**
1. Clone this repository. cd into the repository root directory.
2. In the Organization Management account, create a stack in AWS CloudFormation console at https://console.aws.amazon.com/cloudformation.
3. On the Specify stack details page, type a stack name in the Stack name box. You can choose any name, such as, *delegate-IC-admin*.
4. In the Parameters section, specify the following parameters:
    - delegate: true
    - accountid: 123456789012 (Account Id of the account you'd like to delegate as administrator)
5. Choose Next to proceed with setting options for your stack and create the stack.
6. Once the CloudFormation stack is created successfully, follow the steps under Deployment section below.

#### Deployment in delegated administrator account
1. Clone this repository. cd into the repository root directory.
2. Create an AWS CodeCommit repository or a [CodeStar connection](https://docs.aws.amazon.com/dtconsole/latest/userguide/connections-create.html) to connect to your git repository. The AWS CodeCommit repository or the CodeStar Connection must exist prior to deploying codepipeline-stack.template in next step.
    - If you chose CodeCommit, the name of CodeCommit repository will be used when we create pipeline with codepipeline-stack.template.
    - If you created a CodeStar Connection, the full connection ARN of the CodeStar Connection will be used when we create pipeline with codepipeline-stack.template.
3. Specify parameter values in *identity-center-stacks-parameters.json* file in the repository. Those parameters will be used by the CodePipeline to create other 2 CloudFormation stacks.
    - The value of *"ICMappingBucketName"* parameter is used by both codepipeline-stack.template and identity-center-stacks-parameters.json.
    - As you've chosen to manage Identity Center in a delegated administrator account, the value of *"AdminDelegated"* must be **true**.
    - If you have Control Tower enabled, change the value of *"ControlTowerEnabled"* to "true", else, keep it "false".
    - If you have an existing IAM role or a user to manage Identity Center without triggering notifications for manual changes, add the ARN of the existing IAM role or user to *"ICAutomationAdminArn"* and change the value of *"createICAdminRole"* to "false". If you do not have an existing IAM role or a user, leave the value of *"ICAutomationAdminArn"* empty '' and change the value of *"createICAdminRole"* to true and the solution will create an IAM role for you.
    - If you have an existing IAM role or a user to administer KMS key used to encrypt S3 bucket for Identity Center solution, without triggering notifications for manual changes, add the ARN of the existing IAM role or user to *"ICKMSAdminArn"* and change the value of *"createICKMSAdminRole"* to "false". If you do not have an existing IAM role or a user, leave the value of *"ICKMSAdminArn"* empty '' and change the value of *"createICKMSAdminRole"* to true and the solution will create an IAM role for you.
    - You can provide your email address or a distribution list as avalue for *"SNSEmailEndpointSubscription"* to receive SNS notifications for manual changed detected within Identity Center.
    - If you'd like the solution to create a KMS key to encrypt ICMappingBucket, set *"createS3KmsKey"* to "true". Alternatively, if you wish to use an existing KMS key, set the *"createS3KmsKey"* to false and provide your KMS key ARN to *"S3KmsArn"*. Please note that if you choose to provide your KMS key, you'd need to ensure proper KMS key policy and management. 
4. In your delegated administrator account, use the codepipeline-stack.template cloudformation template to provision the AWS Code Pipeline and related CICD resources in the same region that IAM Identity Center service is enabled. On the Specify stack details page, type a stack name in the Stack name box. You can choose any name, such as, *id-center-pipeline-stack*.
5. In the Parameters section, specify the following parameters:
    - *GeneratePermissionSetsAndMappings*: Set to true if you want to deploy a separate build project to generate permission sets and mapping JSON files, ONLY if you are already using Identity Center and would like to import existing permission sets and assignments into this solution. Please note that you must manually upload `src/automation-code/permission-set-and-mapping-files-generator/auto-generate-permissionsets-mapping-files.py` file to the S3 Bucket and run the build project to generate permission sets and mapping files before pushing code to your source code repository. The name of the S3 Bucket and the Build Project can be found in Outputs section of the stack once the codepipeline-stack.template is deployed successfully.
    - *ICInstanceARN*: Required when GeneratePermissionSetsAndMappings is set to true. ICInstanceARN can be found on the AWS IAM Identity Center console 'Settings' page.
    - *IdentityStoreId*: Required when GeneratePermissionSetsAndMappings is set to true. Identity Store ID can be found on the AWS IAM Identity Center console 'Settings' page.
    - *AutomationBuildProjectName*: Specify the name for the automation CodeBuild projects or leave default.
    - *ICMappingBucketName*: The same bucket name will be used in the automation and s3 stack. This S3 bucket is used to store the permission sets and mapping files. **Specify the same name you have specified in identity-center-stacks-parameters.json**.
    - *SourceType*: Choose the source type for your pipeline (AWS CodeCommit or CodeStarConnection).
    - *ConnectionArn*: The ARN of the CodeStar connection (**required if you set SourceType as CodeStarConnection**).
    - *RepositoryName*: The name of the repository (full name of repository with path for CodeStarConnection; repository name for AWS CodeCommit).
    - *RepoBranch*: The name of branch that will trigger the CodePipeline run. Default is 'main'.
    - *SNSPipelineApprovalEmail*: The email that will receive and approve pipeline approval notifications.
6. (Optional) If you set *GeneratePermissionSetsAndMappings* to 'true', upload the *src/automation-code/permission-set-and-mapping-files-generator/auto-generate-permissionsets-mapping-files.py* file to the root of the S3 bucket (Bucket name starts with 'icpermsetmapping'). Once uploaded, navigate to CodeBuild > Build Projects > IC-GeneratePermissionSetsAndMappingFiles and hit Start Build. This will read your existing Identity Center configuration and generate a *identity-center-mapping-info* folder with necessary files in the S3 Bucket.
7. Create your own permission sets json defination files as well as the account assignment defination file "global-mapping.json" and "target-mapping.json". Note, if you chose to perform the optional Step 6 above, the existing permission sets and mapping files will be in the S3 bucket. You can replace the files in *identity-center-mapping-info* folder in this repository with the one generated in the S3 bucket.
8. Push the following files to your CodeCommit repository, e.g. Linux tree structure:
```
├── LICENSE
├── README.md
├── codepipeline-stack.template
├── delegate-admin
│   ├── IC-Delegate-Admin.template
│   └── IC_delegate_admin_main.py
├── diagram
│   └── architecture_diagram.png
├── identity-center-automation.template
├── identity-center-mapping-info
│   ├── global-mapping.json
│   ├── permission-sets
│   │   ├── example-1.json
│   │   ├── example-2.json
│   │   ├── example-3.json
│   │   ├── ...
│   │   └── example-99.json
│   └── target-mapping.json
├── identity-center-s3-bucket.template
├── identity-center-stacks-parameters.json
└── src
    ├── automation-code
    │   ├── identity-center-auto-assign
    │   │   ├── auto-assignment.py
    │   │   └── cfnresponse.py
    │   ├── identity-center-auto-permissionsets
    │   │   ├── auto-permissionsets.py
    │   │   └── cfnresponse.py
    │   └── permission-set-and-mapping-files-generator
    │       └── auto-generate-permissionsets-mapping-files.py
    ├── codebuild
    │   ├── buildspec-mapping.yml
    │   ├── buildspec-param.yml
    │   ├── buildspec-validation.yml
    │   └── buildspec-zipfiles.yml
    └── validation
        └── syntax-validator.py
```
9. The pipeline will automatically create 2 new CloudFormation stacks *IdentityCenter-S3-Bucket-Stack* and *IdentityCenter-Automation-Stack* in your account and upload your permission sets and mapping files to a centralized S3 bucket. The non-default parameters are specified in identity-center-stacks-parameters.json file.
10. The 'ReviewAndExecute' stage needs manual approval before the Pipeline invoke the CodeBuild Project. Once the pipeline is completed, verify the permission sets and account mapping on the AWS IAM Identity Center service console.


### How to implement this solution in Organization Management account:
1. Clone this repository. cd into the repository root directory.
2. Create an AWS CodeCommit repository or a [CodeStar connection](https://docs.aws.amazon.com/dtconsole/latest/userguide/connections-create.html) to connect to your git repository. The AWS CodeCommit repository or the CodeStar Connection must exist prior to deploying codepipeline-stack.template in next step.
    - If you chose CodeCommit, the name of CodeCommit repository will be used when we create pipeline with codepipeline-stack.template.
    - If you created a CodeStar Connection, the full connection ARN of the CodeStar Connection will be used when we create pipeline with codepipeline-stack.template.
3. Specify parameter values in *identity-center-stacks-parameters.json* file in the repository. Those parameters will be used by the CodePipeline to create other 2 CloudFormation stacks.
    - The value of *"ICMappingBucketName"* parameter is used by both codepipeline-stack.template and identity-center-stacks-parameters.json.
    - As you've chosen to manage Identity Center in Organization Management account, the value of AdminDelegated must be **false**.
    - If you have Control Tower enabled, change the value of *"ControlTowerEnabled"* to "true", else, keep it "false".
    - If you have an existing IAM role or a user to manage Identity Center without triggering notifications for manual changes, add the ARN of the existing IAM role or user to *"ICAutomationAdminArn"* and change the value of *"createICAdminRole"* to "false". If you do not have an existing IAM role or a user, leave the value of *"ICAutomationAdminArn"* empty '' and change the value of *"createICAdminRole"* to true and the solution will create an IAM role for you.
    - If you have an existing IAM role or a user to administer KMS key used to encrypt S3 bucket for Identity Center solution, without triggering notifications for manual changes, add the ARN of the existing IAM role or user to *"ICKMSAdminArn"* and change the value of *"createICKMSAdminRole"* to "false". If you do not have an existing IAM role or a user, leave the value of *"ICKMSAdminArn"* empty '' and change the value of *"createICKMSAdminRole"* to true and the solution will create an IAM role for you.
    - You can provide your email address or a distribution list as avalue for *"SNSEmailEndpointSubscription"* to receive SNS notifications for manual changed detected within Identity Center.
    - If you'd like the solution to create a KMS key to encrypt ICMappingBucket, set *"createS3KmsKey"* to "true". Alternatively, if you wish to use an existing KMS key, set the *"createS3KmsKey"* to false and provide your KMS key ARN to *"S3KmsArn"*. Please note that if you choose to provide your KMS key, you'd need to ensure proper KMS key policy and management. 
4. In your AWS Organization Management account, use the codepipeline-stack.template cloudformation template to provision the AWS Code Pipeline and related CICD resources in the same region that IAM Identity Center service is enabled. On the Specify stack details page, type a stack name in the Stack name box. You can choose any name, such as, *id-center-pipeline-stack*.
5. In the Parameters section, specify the following parameters:
    - *GeneratePermissionSetsAndMappings*: Set to true if you want to deploy a separate build project to generate permission sets and mapping JSON files, ONLY if you are already using Identity Center and would like to import existing permission sets and assignments into this solution. Please note that you must manually upload `src/automation-code/permission-set-and-mapping-files-generator/auto-generate-permissionsets-mapping-files.py` file to the S3 Bucket and run the build project to generate permission sets and mapping files before pushing code to your source code repository. The name of the S3 Bucket and the Build Project can be found in Outputs section of the stack once the codepipeline-stack.template is deployed successfully.
    - *ICInstanceARN*: Required when GeneratePermissionSetsAndMappings is set to true. ICInstanceARN can be found on the AWS IAM Identity Center console 'Settings' page.
    - *IdentityStoreId*: Required when GeneratePermissionSetsAndMappings is set to true. Identity Store ID can be found on the AWS IAM Identity Center console 'Settings' page.
    - *AutomationBuildProjectName*: Specify the name for the automation CodeBuild projects or leave default.
    - *ICMappingBucketName*: The same bucket name will be used in the automation and s3 stack. This S3 bucket is used to store the permission sets and mapping files. **Specify the same name you have specified in identity-center-stacks-parameters.json**.
    - *SourceType*: Choose the source type for your pipeline (AWS CodeCommit or CodeStarConnection).
    - *ConnectionArn*: The ARN of the CodeStar connection (**required if you set SourceType as CodeStarConnection**).
    - *RepositoryName*: The name of the repository (full name of repository with path for CodeStarConnection; repository name for AWS CodeCommit).
    - *RepoBranch*: The name of branch that will trigger the CodePipeline run. Default is 'main'.
    - *SNSPipelineApprovalEmail*: The email that will receive and approve pipeline approval notifications.
6. (Optional) If you set *GeneratePermissionSetsAndMappings* to 'true', upload the *src/automation-code/permission-set-and-mapping-files-generator/auto-generate-permissionsets-mapping-files.py* file to the root of the S3 bucket (uckent name starts with 'icpermsetmapping'). Once uploaded, navigate to CodeBuild > Build Projects > IC-GeneratePermissionSetsAndMappingFiles and hit Start Build. This will read your existing Identity Center configuration and generate a *identity-center-mapping-info* folder with necessary files in the S3 Bucket.
7. Create your own permission sets json defination files as well as the account assignment defination file "global-mapping.json" and "target-mapping.json". Note, if you chose to perform the optional Step 6 above, the existing permission sets and mapping files will be in the S3 bucket. You can replace the files in *identity-center-mapping-info* folder in this repository with the one generated in the S3 bucket.
8. Push the following files to your git repository, e.g. Linux tree structure:
```
├── LICENSE
├── README.md
├── codepipeline-stack.template
├── delegate-admin
│   ├── IC-Delegate-Admin.template
│   └── IC_delegate_admin_main.py
├── diagram
│   └── architecture_diagram.png
├── identity-center-automation.template
├── identity-center-mapping-info
│   ├── global-mapping.json
│   ├── permission-sets
│   │   ├── example-1.json
│   │   ├── example-2.json
│   │   ├── example-3.json
│   │   ├── ...
│   │   └── example-99.json
│   └── target-mapping.json
├── identity-center-s3-bucket.template
├── identity-center-stacks-parameters.json
└── src
    ├── automation-code
    │   ├── identity-center-auto-assign
    │   │   ├── auto-assignment.py
    │   │   └── cfnresponse.py
    │   ├── identity-center-auto-permissionsets
    │   │   ├── auto-permissionsets.py
    │   │   └── cfnresponse.py
    │   └── permission-set-and-mapping-files-generator
    │       └── auto-generate-permissionsets-mapping-files.py
    ├── codebuild
    │   ├── buildspec-mapping.yml
    │   ├── buildspec-param.yml
    │   ├── buildspec-validation.yml
    │   └── buildspec-zipfiles.yml
    └── validation
        └── syntax-validator.py
```
9. The pipeline will automatically create 2 new CloudFormation stacks *IdentityCenter-S3-Bucket-Stack* and *IdentityCenter-Automation-Stack* in your account and upload your permission sets and mapping files to a centralized S3 bucket. The non-default parameters are specified in identity-center-stacks-parameters.json file.
10. The 'ReviewAndExecute' stage needs manual approval before the Pipeline invoke the CodeBuild Project. Once the pipeline is completed, verify the permission sets and account mapping on the AWS IAM Identity Center service console.


**Note:** If you chose to create IAM role for Identity Center and KMS admin, the ARNs of those roles can be found in the output tab of the *IdentityCenter-S3-Bucket-Stack* in AWS CloudFormation console. To make manual changes to Identity Center without triggering notifications, you can assume the *ICAdminRole* role. View steps on [how to assume a role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-console.html).


### Architecture Diagram

  ![Image of Identity_Center_Solution_Diagram](diagram/architecture_diagram.png) 

### This solution covers the following scenarios:
- If any change had been made through another approach without updating JSON mapping files in the source, such as deleting a permission set, will this solution be able to detect and fix those drifts?
    -   A: Yes. The automation will use the mapping definitions in the s3 bucket as the single source of truth. When the CodeBuild automation function runs, it compares the information in loaded mapping definitions and assignments in the current environment. So it's able to find and address the drifts by re-provisioning the missing assignments and removing the additional assignments from IAM Identity Center.

    The following s3 bucket policy will block all PutObject/DeleteObject actions to this IAM Identity Center s3 bucket, Except the privileged automation roles. This ensures no one other than privileged automation pipeline role is able to change the content of the mapping definition file in s3 bucket.
```
          - Sid: OnlyAllowObjectUpdateRole1
            Action:
              - s3:DeleteObject
              - s3:DeleteObjectVersion
              - s3:PutObject
              - s3:PutObjectAcl
            Effect: Deny
            Principal: "*"
            Resource:
              !Sub arn:aws:s3:::${rS3Bucket}/*
            Condition:
              ArnNotLike:
                aws:PrincipalArn:
                  - !Sub "arn:aws:iam::${AWS::AccountId}:role/ICAutoPipelineCodeBuildRole"
                  - !Ref ICAutomationAdminArn
```
  - Another bucket policy blocks all PutBucketPolicy and DeleteBucketPolicy actions if those request are not from AWSCloudFormationStackSetExecutionRole or privileged automation role.
```
          - Sid: OnlyAllowObjectUpdateRole2
            Action:
              - s3:PutBucketPolicy
              - s3:DeleteBucketPolicy
            Effect: Deny
            Principal: "*"
            Resource:
              !Sub arn:aws:s3:::${rS3Bucket}
            Condition:
              ArnNotLike:
                aws:PrincipalArn:
                  - !Sub "arn:aws:iam::${AWS::AccountId}:role/ICAutoPipelineCodeBuildRole"
                  - !Ref ICAutomationAdminArn
```
    Additionally, the CodeBuild Project tracks and uses versioned objects in S3 to ensure integrity and prevent manual manipulation of configuration files.

### (Optional) Detect the manual modifications to the IAM Identity Center to trigger immediate baseline actions.
- There are 2 optional AWS event rules in the identity-center-automation.template:

    - ICManualActionDetectionRule1
      - Monitor the APIs from source 'sso.amazonaws.com'
    - ICManualActionDetectionRule2
      - Monitor the APIs from source 'sso-directory.amazonaws.com'

These 2 event rules will trigger the CodeBuild project when AWS detects manual write changes to IAM Identity Center. Those AWS events will also trigger the lambda function to send out Email notification to administrators via SNS service.
Note - Events initiated from source 'sso-directory.amazonaws.com' will not be reverted as those are events related to users and groups. This is by design because customers may choose to integrate an external identity provider, such as EntraID, with Identity Center and the changes to users and groups must be done in the external identity provider.

### Can we use Account Name or Organization Unit (OU) Name instead of Account ID?
-  Yes, this solution allows you to use 12-digit account IDs, Account Names and Organization Unit (OU) Names at the same time for ease of use. For account ID, you can specify a 12-digit account ID directly, for account name, use 'name:' prefix, and for OU name, use 'ou:' prefix. Example target mapping JSON configuration:
  ```

    [
        {
            "TargetGroupName": "Target_Group_A",
            "PermissionSetName": [
                "<Name_permission_set_A>"  ],
            "TargetAccountid": [
                "111111111111",
                "123456789012"
                "name:Audit",
                "name:ProdAccount",
                "ou:Infrastructure",
                "ou:Development"
            ]
        },
        {
            "TargetGroupName": "Target_Group_B",
            "PermissionSetName": [
                "<Name_permission_set_B>" ],
            "TargetAccountid": [
                "888888888888",
                "999999999999"
            ]
        },
        {       ....
        }
    ]
  ```

### An existing permission set needs to be updated in all accounts it is mapped to.

- The identity-center-auto-permissionsets function will make "ProvisionPermissionSet" IAM Identity Center API call to update assignment status after it detects any updates to the existing permission sets.

### An existing permission set is deleted
-  This solution will detach the permission set from all mapped accounts before deleting.

### When a new AWS account is created, or an existing AWS account is invited to the current organization.
- This solution detects the API calls "CreateAccountResult" with SUCCEEDED status and "AccountJoinedOrganization" and uses them to trigger the IAM Identity Center group assignment tasks when a new account is successfully created or joined by invitation.

### A single AD or IAM Identity Center group needs permission set A for account 1, and permission set B for account 2.
-  The solution covers this use case. For example, we can add following content to "target-mapping-definition.json" file, so that identity-center-auto-assignments function will perform 2 separate assignments so we can attach this IAM Identity Center group to account 111111111111 and 123456789012 with permission set A and attach the same IAM Identity Center group to account 888888888888 and 999999999999 with permission set B:
  ```

    [
        {
            "TargetGroupName": "Target_Group_A",
            "PermissionSetName": [
                "<Name_permission_set_A>"  ],
            "TargetAccountid": [
                "111111111111",
                "123456789012"
            ]
        },
        {
            "TargetGroupName": "Target_Group_B",
            "PermissionSetName": [
                "<Name_permission_set_B>" ],
            "TargetAccountid": [
                "888888888888",
                "999999999999"
            ]
        },
        {       ....
        }
    ]
  ```
### A new AD or Identity Center group is created and needs an existing permission set and account mapping assigned to it.
- The new AD or Identity Center group can be added by updating the global or target mapping JSON file.

### A new AD or Identity Center group is created and needs an existing permission set assigned to a new account / list of accounts.
- The new AD or Identity Center group can be added by updating the global or target mapping JSON file.

### A new AD or Identity Center group is created and needs a new permission set assigned to existing or new accounts
- We need to first create a new permission set definition JSON file for the new permission set. Once the new permission set is created in the Management account, then update the Identity Center group mapping JSON file to trigger the CodeBuild Project.

### ICAutomationAdmin Role was used to make a manual change to Identity Center without triggering the manual revert, in an event of an incident when waiting for the pipeline execution was not feasible.
- The ICScheduledRuleBaselining EventBridge Rule is configured to run every 12 hours to baseline permissions automatically by invoking the automation CodeBuild Project.
---

## Examples of mapping files
1. Example of permission set file (random account ids):

    Note: This solution(version 1.1.0 or newer) supports 1)customer managed policy and 2) session duration feature in the permission set definition file:
    1. Only use the "CustomerPolicies" object in the definition file if you need to apply customer managed policy to your permission set. When you create a permission the set with a customer managed policy, you MUST create an IAM policy with the same name and path in each AWS account where IAM Identity Center assigns your permission set. If you are specifying a custom path, make sure to specify the same path in each AWS account.
    2. You can apply custom permission set *session duration* for selected permission by adding "Session_Duration" in the mapping file (e.g 1-example-admin). You can set your own default permission set "SessionDuration" in the identity-center-automation.template or using identity-center-stacks-parameters.json file, current default value is 1 hour.
        - To change the "Session_Duration" on existing permission set:
            - Option 1) Recreate the permission set using CICD pipeline
            - Option 2) Update the both  "Session_Duration" and "Description" section in the definition file and re-run the pipeline.

```

{
    "Name": "1-example-admin",
    "Description": "1-example-admin",
    "Session_Duration": "PT12H",
    "Tags": [
        {
            "Key": "identity-center-solution",
            "Value": "example"
        }
    ],
    "ManagedPolicies": [
        {
            "Name": "AdministratorAccess",
            "Arn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    ],
    "CustomerPolicies": [
        {
            "Name": "customer-managed-policy-1",
            "Path": "/IAM-path-example/"
        },
        {
            "Name": "customer-managed-policy-2",
            "Path": "/"
        }
    ],
    "InlinePolicies": []
}

```
2. Example of global mapping file:
```
[
    {
        "GlobalGroupName": "Example_1-global-admin",
        "PermissionSetName": [
            "1-example-admin"
        ],
        "TargetAccountid": "Global"
    },
    {
        "GlobalGroupName": "Example_2-global-reader",
        "PermissionSetName": [
            "2-example-readonly"
        ],
        "TargetAccountid": "Global"
    },
]
```
3. Example of target mapping file:
```
[
    {
        "TargetGroupName": "Example_8-splunk-admin",
        "PermissionSetName": [
            "ops-enterprisemonitoring"
        ],
        "TargetAccountid": [
            "123456789012"
        ]
    },
    {
            "TargetGroupName": "Example_9-Data-user",
            "PermissionSetName": [
                "data-end-user",
                "db-read-write"
                ],
            "TargetAccountid": [
                "111111111111",
                "123456789012"
                "name:Audit",
                "name:ProdAccount",
                "ou:Infrastructure",
                "ou:Development"
            ]
        },
	  {
        "TargetGroupName": "Example_10-network-engineering",
        "PermissionSetName": [
            "10-ops-networking",
            "ops-enterprisemonitorin"
        ],
        "TargetAccountid": [
            "123456789012",
			"111111111111",
			"222222222222",
			"333333333333"
        ]
    }
]
```

## Cleanup Steps
- **Tearing down Identity Center resources could interrupt your access to AWS accounts.** Please make sure you have other IAM roles or users to login the accounts. The following steps will only remove the resources that provisioned by this solution. You will need to manually remove other permission sets or SIdentity CenterSO assigments that are created outside this automation.
    1. Replace all the mapping information with an empty list "[]" in  global-mapping.json and target-mapping.json files.
    Then re-run the pipeline to let CodeBuild remove all the Identity Center assignments.
    2. Delete all the permission set JSON files in the "permissions-set" folder
    Then re-run the pipeline to automatically remove all permission sets.
    3. Delete CloudFormation stack that was created with identity-center-automation.template.
    4. Delete CloudFormation stack that was created with identity-center-s3-bucket.template
    5. Delete CloudFormation stack that was created with code-pipeline-stack.template

## Troubleshoot
1. For the issue with AWS CloudFormation stack, you can view the error message in the stack events and refer to [Troubleshooting CloudFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/troubleshooting.html).
2. For AWS CodePipeline issue, you can review the error messages on the CodePipeline console. For IAM related issue, please check [Troubleshooting AWS CodePipeline identity and access](https://docs.aws.amazon.com/codepipeline/latest/userguide/security_iam_troubleshoot.html).
3. The default log groups for the automation functions within CodeBuild Project, and manual change notification Lambda function are ic-permissionsets-enabler-AccountId-Region, ic-auto-assignment-enabler-AccountId-Region and  */aws/lambda/ic-alert-SNSnotification*. This is in addition to the build logs provided by CodeBuild. 

---
## License
(c) 2020 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
This AWS Content is provided subject to the terms of the AWS Customer Agreement available at
http://aws.amazon.com/agreement or other written agreement between Customer and Amazon Web Services, Inc.