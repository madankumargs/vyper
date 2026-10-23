# AWS SAM deployment guide

The template uses AWS SAM because it expresses the S3 object-created trigger and its permission with fewer manual resources than plain CloudFormation.

## Prerequisites

- AWS CLI and AWS SAM CLI installed and configured with permission to create CloudFormation stacks, S3 buckets, Lambda roles/functions, SNS, and CloudWatch log groups.
- A deployment region and a unique bucket namespace. The template lets CloudFormation generate bucket names.
- If enabling Bedrock, an account-approved model ID with model access enabled in that region. Optional guardrail IDs must also exist there.
- Review current AWS Lambda, S3, SNS, CloudWatch Logs, and Bedrock pricing before running this pipeline. Upload volume and model calls affect cost.

## Deploy

From the repository root:

```sh
sam validate --template-file aws/template.yaml
sam build --template-file aws/template.yaml
sam deploy --template-file .aws-sam/build/template.yaml --guided
```

Set `EnableBedrock=false` unless the account has model access configured. To enable it, set `EnableBedrock=true`, provide `BedrockModelId`, and optionally `GuardrailId`. The template enables S3 Object Lock only at input bucket creation when `EnableObjectLock=true`; choose retention separately after legal and operational review.

Upload a validated access snapshot JSON to the stack's input bucket. The Lambda writes JSON, Markdown, and HTML report objects under the same key prefix in the reports bucket. It publishes only aggregate HIGH/CRITICAL counts and the org score to SNS; it does not include identity or evidence details.

## Teardown

Remove input objects and all report objects first, including prior object versions if versioning is enabled. For an Object Lock-enabled bucket, legal holds or retention periods may prevent deletion. Then delete the stack:

```sh
aws cloudformation delete-stack --stack-name STACK_NAME --region REGION
```

## Validation status

This deployment was not performed. AWS credentials, account permissions, Bedrock access, and a target region were not available for validation. The handler is exercised locally with in-memory S3 and SNS stubs. `cfn-lint` validation status is recorded in `ACCESS_RISK_STATUS.md`.

`state_machine.asl.json` is an optional design artifact only. It contains a callback-token approval wait and a terminal decision-recording no-op; the placeholder approval Lambda ARN must be replaced by an operator-owned integration. It is not deployed or included in the SAM stack and does not perform revocation.
