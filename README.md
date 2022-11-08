# CICD to Automate IAM Identity Center Permission sets Mapping and Assignments for AWS Organizations

## Background Information

AWS IAM Identity Center (successor to AWS Single Sign-On) provides account assignment APIs and AWS CloudFormation support to automate access across AWS Organizations accounts. With those available APIs, this solution allows all access provided via the IAM Identity Center services to be automated via API / CloudFormation templates, and managed as code converting all currently manual activities.

AWS IAM Identity Center requires the [AWS Organizations service](https://console.aws.amazon.com/organizations) enabled in your AWS account.

## What this solution is
 - Use AWS CodeCommit to securely source control your own IAM Identity Center code repository. Utilize CodePipeline to create and update CloudFormation stacks of IAM Identity Center and other AWS services. 
    - The AWS CodePipeline will first deploy CloudFormation stacks to create a security S3 bucket, automation Lambda functions and other AWS resources.
    - Once the CloudFormation stack is completed, CodePipeline syncs all the mapping files to a Secure S3 bucket
    - Pipeline invokes the Lambda to create IAM Identity Center resources by referring the JSON files in the s3 bucket.
## Solution Instruction

## Prerequisite 
1. AWS Organizations and IAM Identity Center are enabled.
2. [S3 Data event](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html) is enabled for IAM Identity Center source S3 bucket in account's CloudTrail service.
    - Because this solution uses AWS S3 Object-level API to trigger the lambda automation and those Data events are enabled by default. [Additional charges apply](https://aws.amazon.com/cloudtrail/pricing/)
    

### How to implement this solution in Organization primary account:
1. Create an AWS CodeCommit repository.
    - The name of CodeCommit repository will be used when we create pipeline with codepipeline-stack.template.
2. In your AWS Organization primary account, use the codepipeline-stack.template cloudformation template to provision the AWS Code Pipeline and related CICD resources in the same region that IAM Identity Center service is enabled. 
3. Specify parameter values in *identity-center-stacks-parameters.json* file. Those parameters will be used by the CodePipeline to create other 2 CloudFormation stacks.
    - The value of *"ICMappingBucketName"* parameter is used by both codepipeline-stack.template and identity-center-stacks-parameters.json.
4. Create your own  permission sets json defination files  as well as the account assignment defination file "global-mapping.json" and "target-mapping.json".
5. Push the following files to your CodeCommit repository, e.g. Linux tree structure:
```
.
├── LICENSE
├── README.md
├── diagram
│   └── architecture_diagram.jpg
├── src
│   ├── codebuild
│   │   ├── buildspec-mapping.yml
│   │   ├── buildspec-param.yml
│   │   └── buildspec-zipfiles.yml
│   └── lambda-code
│       ├── identity-center-auto-assign
│       │   ├── auto-assignment.py
│       │   └── cfnresponse.py
│       └── identity-center-auto-permissionsets
│           ├── auto-permissionsets.py
│           └── cfnresponse.py
├── identity-center-automation.template
├── codepipeline-stack.template
├── identity-center-s3-bucket.template
└── identity-center-stacks-parameters.json
└── identity-center-mapping-info
    ├── global-mapping.json
    └── target-mapping.json
    └── permission-sets
        ├── example-1.json
        └── example-2.json
        └── ...
        └── example-99.json
```
6. The pipeline will automatically create 2 new CloudFormation stacks *IdentityCenter-S3-Bucket-Stack* and *IdentityCenter-Automation-Stack* in your account and upload your permission sets and mapping files to a centralized S3 bucket. The non-default parameters are specified in identity-center-stacks-parameters.json file.
7. The 'ReviewAndExecute' stage needs manual approval before the Pipeline invoke the Lambda function. Once the pipeline is completed, verify the permission sets and account mapping on the AWS IAM Identity Center service console.

### Architecture Diagram
  
  ![Image of Identity_Center_Solution_Diagram](diagram/architecture_diagram.png)

### This solution covers the following scenarios:
- If any change had been made through another approach without updating JSON mapping files in the source, such as deleting a permission set, will this solution be able to detect and fix those drifts? 
    -   A: Yes. The automation will use the mapping definitions in the s3 bucket as the single source of truth. When the lambda automation function runs, it compares the information in loaded mapping definitions and assignments in the current environment. So it's able to find and address the drifts by re-provisioning the missing assignments and removing the additional assignments from IAM Identity Center.

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
### (Optional) Detect the manual modifications to the IAM Identity Center to trigger immediate baseline actions.
- There are 2 optional AWS event rules in the identity-center-automation.template:

    - ICManualActionDetectionRule1
      - Monitor the APIs from source 'sso.amazonaws.com'
    - ICManualActionDetectionRule2
      - Monitor the APIs from source 'sso-directory.amazonaws.com'

These 2 event rules will trigger the lambda function when AWS detects manual write changes to IAM Identity Center. Those AWS events will also trigger the lambda function to send out Email notification to administrators via SNS service. 

### An existing permission set needs to be updated in all accounts it is mapped to.

- The identity-center-auto-permissionsets Lambda function will make "ProvisionPermissionSet" IAM Identity Center API call to update assignment status after it detects any updates to the existing permission sets.

### An existing permission set is deleted
-  This solution will detach the permission set from all mapped accounts before deleting.

### When a new AWS account is created, or an existing AWS account is invited to the current organization.
- This solution detects the API calls "CreateAccount" and "InviteAccountToOrganization" and uses them to trigger the IAM Identity Center group assignment tasks.

### A single AD or IAM Identity Center group needs permission set A for account 1, and permission set B for account 2.
-  The solution covers this use case. For example, we can add following content to "target-mapping-definition.json" file, so that lambda function will perform 2 separate assignments so we can attach this IAM Identity Center group to account 111111111111 and 123456789012 with permission set A and attach the same IAM Identity Center group to account 888888888888 and 999999999999 with permission set B: 
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
- We need to first create a new permission set definition JSON file for the new permission set. Once the new permission set is created in the primary account, then update the Identity Center group mapping JSON file to trigger the lambda function.

---

## Examples of mapping files
1. Example of permission-set file (random account ids):

    Note: This solution(version 1.1.0 or newer) supports advanced customer managed policy feature in the permission-set definition file:
    1. Only use "CustomerPolicies" object in the definition file if you need to apply customer managed policy to your permission-set.
    2. When you create a permission set with a customer managed policy, you MUST create an IAM policy with the same name and path in each AWS account where IAM Identity Center assigns your permission set. If you are specifying a custom path, make sure to specify the same path in each AWS account.

```

{
    "Name": "1-example-admin",
    "Description": "1-example-admin",
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

## Cleanup Steps
- **Tearing down Identity Center resources could interrupt your access to AWS accounts.** Please make sure you have other IAM roles or users to login the accounts. The following steps will only remove the resources that provisioned by this solution. You will need to manually remove other permission sets or SIdentity CenterSO assigments that are created outside this automation.
    1. Replace all the mapping information with an empty list "[]" in  global-mapping.json and target-mapping.json files. 
    Then re-run the pipeline to let lambda remove all the Identity Center assignments.
    2. Delete all the permission set JSON files in the "permissions-set" folder
    Then re-run the pipeline to automatically remove all permission sets.
    3. Delete CloudFormation stack that was created with identity-center-automation.template.
    4. Delete CloudFormation stack that was created with identity-center-s3-bucket.template
    5. Delete CloudFormation stack that was created with code-pipeline-stack.template

## Troubleshoot
1. For the issue with AWS CloudFormation stack, you can view the error message in the stack events and refer to [Troubleshooting CloudFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/troubleshooting.html).
2. For AWS CodePipeline issue, you can review the error messages on the CodePipeline console. For IAM related issue, please check [Troubleshooting AWS CodePipeline identity and access](https://docs.aws.amazon.com/codepipeline/latest/userguide/security_iam_troubleshoot.html).
3. The default log groups for the automation lambda functions are */aws/lambda/ic-permissionsets-enabler*, */aws/lambda/ic-auto-assignment-enabler* and  */aws/lambda/ic-alert-SNSnotification*.

---
## License
(c) 2020 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
This AWS Content is provided subject to the terms of the AWS Customer Agreement available at
http://aws.amazon.com/agreement or other written agreement between Customer and Amazon Web Services, Inc.