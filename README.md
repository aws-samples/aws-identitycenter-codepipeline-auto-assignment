# CICD to Automate SSO Permission sets Mapping and Assignments for AWS Organizations

## Background Information

AWS Single Sign-On (SSO) adds new account assignment APIs and AWS CloudFormation support to automate access across AWS Organizations accounts. With those available SSO APIs, this solution allows all access provided via the SSO services to be automated via API / CloudFormation templates, and managed as code converting all currently manual activities.

AWS SSO requires the [AWS Organizations service](https://console.aws.amazon.com/organizations) enabled in your AWS account.

## What this solution is
 - Use AWS CodeCommit to securely source control your own SSO code repository,Utilize CodePipeline to create and update CloudFormation stacks of SSO and other AWS services. 
    - The AWS CodePipeline will first deploy CloudFormation stacks to create a security S3 bucket, automation Lambda functions and other AWS resources.
    - Once the CloudFormation stack is completed, CodePipeline syncs all the mapping files to a Secure S3 bucket
    - Pipeline invokes the Lambda to create SSO resources by referring the JSON file in the s3 bucket.
## Solution Instruction

## Prerequisite 
1. Make sure [S3 Data event](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html) is enabled for SSO source S3 bucket in account's CloudTrail service.
    - Because this solution uses AWS S3 Object-level API to trigger the lambda automation and those Data events are enabled by default. [Additional charges apply](https://aws.amazon.com/cloudtrail/pricing/)
    

### How to implement this solution in Organization primary account:

1. In your AWS Organization primary account, use the sso-codepipeline-stack.template cloudformation template to provision the AWS Code Pipeline and related CICD resources in the same region that SSO service is enabled. Modify the CloudFormation template based on your accounts' information.
2. Create an AWS CodeCommit repository and make sure the name of CodeCommit repository matches the value of "RepositoryName" parameter in your sso-codepipeline-stack.template.
3. Update the CloudFormation parameters in "sso-automation-parameters.json" and "sso-s3-parameters.json" files.
4. Create your own  permission sets json definition files as well as the account assignment "global-mapping.json" and "target-mapping.json" files.
5. Push the following files to your CodeCommit repository:
```
├── LICENSE
├── README.md
├── src
│   ├── codebuild
│   │   ├── buildspec-mapping.yml
│   │   └── buildspec-zipfiles.yml
│   └── lambda-code
│       ├── sso-auto-assign
│       │   ├── auto-assignment.py
│       │   └── cfnresponse.py
│       └── sso-auto-permissionsets
│           ├── auto-permissionsets.py
│           └── cfnresponse.py
├── sso-automation-parameters.json
├── sso-automation.template
├── sso-s3-bucket.template
├── sso-s3-parameters.json
├── sso-codepipeline-stack.template
└── sso-mapping-info
    ├── global-mapping.json
    └── target-mapping.json
    └── permission-sets
        ├── example-1.json
        └── example-2.json
        └── ...
        └── example-99.json

```
6. The pipeline will automatically create 2 new CloudFormation stacks in your account and upload your SSO permission and mapping files to a centralized S3 bucket. The non-default parameters of sso-s3-bucket.template and sso-automation.template are defined in sso-s3-parameters.json and sso-automation-parameters.json
7. The 'ReviewAndExecute' stage needs manual approval before the Pipeline invoke the Lambda function. Once the pipeline is completed, verify the permission sets and account mapping on the AWS SSO service console.

### Architecture Diagram
  
  ![Image of SSO_Solution_Diagram](diagram/architecture_diagram.png)

### This solution covers the following scenarios:
- If any change had been made through another approach without updating JSON mapping files in the source, such as a bitbucket, will this solution be able to detect and fix those drifts? 
    -   A: Yes. The automation will use the mapping definitions (synchronized from bitbucket repository) as the single source of truth(SSOT). When the lambda automation function runs, it compares the information in loaded mapping definitions and assignments in the current environment. So it's able to find and address the drifts by re-provisioning the missing assignments and removing the additional assignments from AWS SSO service.

    The following s3 bucket policy will block all PutObject/DeleteObject actions to this SSO s3 bucket, Except the privileged sso automation role. This ensures no one other than privileged automation pipeline role is able to change the content of the mapping definition file in s3 bucket. 
```
          - Sid: OnlyAllowObjectUpdateJenkinsRole1
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
                aws:PrincipalArn: !Ref pSSOAutmationRole
```
  - Another bucket policy blocks all PutBucketPolicy and DeleteBucketPolicy actions if those request are not from AWSCloudFormationStackSetExecutionRole or privileged sso automation role.
```
          - Sid: OnlyAllowObjectUpdateJenkinsRole2
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
                  - !Ref pJenksinIamARN
                  - !Sub 'arn:aws:iam::${AWS::AccountId}:role/AWSCloudFormationStackSetExecutionRole'
```
### (Optional) Detect the manual modifications to the SSO service to trigger immediate baseline actions.
- There are 2 optional AWS event rules in the sso-automation.template:

    - SSOManualActionDetectionRule1
      - Monitor the APIs from source 'sso.amazonaws.com'
    - SSOManualActionDetectionRule2
      - Monitor the APIs from source 'sso-directory.amazonaws.com'

These 2 event rules will trigger the SSO lambda function when AWS detects manual write changes to SSO Service. Those AWS events will also trigger the lambda function to send out Email notification to administrators via SNS service. 

### An existing permission set needs to be updated in all accounts it is mapped to.

- The sso-auto-permissionsets Lambda function will make "ProvisionPermissionSet" SSO API call to update assignment status after it detects any updates to the existing permission sets.

### An existing permission set is deleted
-  This solution will detach the permission set from all mapped accounts before deleting.

### When a new AWS account is created, or an existing AWS account is invited to the current organization.
- This solution detects the API calls "CreateAccount" and "InviteAccountToOrganization" and uses them to trigger the SSO group assignment tasks.

### A single AD or SSO group needs permission set A for account 1, and permission set B for account 2.
-  The solution covers this use case. For example, we can add following content to "target-mapping-definition.json" file, so that lambda function will perform 2 separate assignments so we can attach this SSO group to account 111111111111 and 123456789012 with permission set A and attach the same SSO group to account 888888888888 and 999999999999 with permission set B: 
  ```

    [
        {
            "TargetGroupName": "SSO_Target_Group_A",
            "PermissionSetName": [
                "<Name_permission_set_A>"  ],
            "TargetAccountid": [
                "111111111111",
                "123456789012"
            ]
        },
        {
            "TargetGroupName": "SSO_Target_Group_B",
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
### A new AD or SSO group is created and needs an existing permission set and account mapping assigned to it.
- The new AD or SSO group can be added by updating the SSO global or target mapping JSON file.

### A new AD or SSO group is created and needs an existing permission set assigned to a new account / list of accounts.
- The new AD or SSO group can be added by updating the SSO global or target mapping JSON file.

### A new AD or SSO group is created and needs a new permission set assigned to existing or new accounts
- We need to first create a new permission set definition JSON file for the new permission set. Once the new permission set is created in the primary account, then update the SSO group mapping JSON file to trigger the lambda function.

---

## Examples of mapping files
1. Example of permission-set file (random account ids):
```
{
    "Name": "1-global-admin",
    "Description": "1-global-admin",
    "Tags": [
        {
            "Key": "sso-solution",
            "Value": "example"
        }
    ],
    "ManagedPolicies": [
        {
            "Name": "AdministratorAccess",
            "Arn": "arn:aws:iam::aws:policy/AdministratorAccess"
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
            "1-global-admin"
        ],
        "TargetAccountid": "Global"
    },
    {
        "GlobalGroupName": "Example_2-global-reader",
        "PermissionSetName": [
            "2-global-reader"
        ],
        "TargetAccountid": "Global"
    },
]
```
3. Example of target mapping file:
```
[
    {
        "TargetGroupName": "Example_9-splunk-admin",
        "PermissionSetName": [
            "9-ops-enterprisemonitoring"
        ],
        "TargetAccountid": [
            "123456789012"
        ]
    },
	  {
        "TargetGroupName": "Example_10-network-engineering",
        "PermissionSetName": [
            "10-ops-networking"
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

## Troubleshoot
1. For the issue with AWS CloudFormation stack, you can view the error message in the stack events and refer to [Troubleshooting CloudFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/troubleshooting.html).
2. For AWS CodePipeline issue, you can review the error messages on the CodePipeline console. For IAM related issue, please check [Troubleshooting AWS CodePipeline identity and access](https://docs.aws.amazon.com/codepipeline/latest/userguide/security_iam_troubleshoot.html).
3. The default log groups for the automation lambda functions are */aws/lambda/sso-permissionses-enabler*, */aws/lambda/sso-auto-assignment-enabler* and  */aws/lambda/sso-alert-SNSnotification*.

## Cleanup Step
#### NOTE. Tearing down SSO could interrupt the access to your AWS accounts. Please make sure you have other IAM roles or users to login the accounts.  
---
1. Replace all the mapping information with an empty list "[]" in global-mapping.json and target-mapping.json files. Then re-run the pipeline to automatically remove all the SSO assignments.
```
[]
```
2. Delete all the permission set JSON files in the "permissions-set" folder
Then re-run the pipeline to automatically remove all permission sets.
3. Delete CloudFormation stack that was created using sso-automation.template
4. Delete CloudFormation stack that was created using sso-s3-bucke.template
5. Delete CloudFormation stack that was created using code-pipeline-stack.template

The above steps will only remove the resources that provisioned by this solution. You may need to manually remove other permission sets or SSO assigments that are created outside this automation.

---
## License
(c) 2020 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
This AWS Content is provided subject to the terms of the AWS Customer Agreement available at
http://aws.amazon.com/agreement or other written agreement between Customer and Amazon Web Services, Inc.