# Discision log 
- CodePipeline will use AWS Code commit as the source for now.
- Split the pipeline stack and the pipeline resource itself.


# CHANGELOG
TBD:
create variables for buildspec projects
## April  20
- README updates
## April  15
- update pipline IAM role permission 
## April  05 v1.1.0
- fixed the kms; logs permission issue for the pipeline code build role
- update the parameter annotation for all the templates
- fixed the incorrect project name referrence in the codepipeline template

## March 20 v1.0.2
- Fixed the assume role issue by removing pipeline role from each build stage
- Added DeletionPolicy: Delete to artifact bucket

## March 20 v1.0.1
- Updated the diagram
- Created the template of creating AWS Codepipeline and build projects. version 1
