This project uses a hybrid of AWS CDK and Terraform to provision all the needed resources
to operate.

CDK is responsible to:
 - Create Lambda function and deploy binary
 - Create API Gateway and register function
 - Create log streams

Terraform is responsible to:
 - Create IAM user for CDK to manage AWS resources
 - Create IAM role for Lambda function to assume and run as
 - Create DynamoDB tables
