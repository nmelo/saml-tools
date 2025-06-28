#!/bin/bash

# Script to set up AWS IAM resources for GitHub Actions deployment
set -e

# Configuration
AWS_PROFILE="${AWS_PROFILE:-default}"
AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --profile $AWS_PROFILE)
GITHUB_REPO="nmelo/saml-tools"
POLICY_NAME="GitHubActionsSAMLToolsPolicy"
USER_NAME="github-actions-saml-tools"
ROLE_NAME="GitHubActionsSAMLToolsRole"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}Setting up AWS resources for GitHub Actions...${NC}"
echo "AWS Account ID: $AWS_ACCOUNT_ID"
echo "AWS Region: $AWS_REGION"
echo "GitHub Repository: $GITHUB_REPO"

# Create IAM policy for GitHub Actions
echo -e "${GREEN}Creating IAM policy...${NC}"
cat > /tmp/github-actions-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ECRAccess",
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:PutImage",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload",
        "ecr:CreateRepository",
        "ecr:DescribeRepositories"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EKSAccess",
      "Effect": "Allow",
      "Action": [
        "eks:DescribeCluster",
        "eks:ListClusters"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EKSClusterAccess",
      "Effect": "Allow",
      "Action": [
        "eks:DescribeCluster"
      ],
      "Resource": "arn:aws:eks:${AWS_REGION}:${AWS_ACCOUNT_ID}:cluster/saml-tools-cluster"
    }
  ]
}
EOF

# Create or update the policy
POLICY_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${POLICY_NAME}"
if aws iam get-policy --policy-arn $POLICY_ARN --profile $AWS_PROFILE 2>/dev/null; then
    echo -e "${YELLOW}Policy already exists, updating...${NC}"
    POLICY_VERSION=$(aws iam get-policy --policy-arn $POLICY_ARN --query 'Policy.DefaultVersionId' --output text --profile $AWS_PROFILE)
    aws iam create-policy-version \
        --policy-arn $POLICY_ARN \
        --policy-document file:///tmp/github-actions-policy.json \
        --set-as-default \
        --profile $AWS_PROFILE
else
    echo -e "${GREEN}Creating new policy...${NC}"
    aws iam create-policy \
        --policy-name $POLICY_NAME \
        --policy-document file:///tmp/github-actions-policy.json \
        --description "Policy for GitHub Actions to deploy SAML tools to EKS" \
        --profile $AWS_PROFILE
fi

# Create IAM user for GitHub Actions
echo -e "${GREEN}Creating IAM user...${NC}"
if ! aws iam get-user --user-name $USER_NAME --profile $AWS_PROFILE 2>/dev/null; then
    aws iam create-user --user-name $USER_NAME --profile $AWS_PROFILE
    echo -e "${GREEN}User created successfully${NC}"
else
    echo -e "${YELLOW}User already exists${NC}"
fi

# Attach policies to the user
echo -e "${GREEN}Attaching policies to user...${NC}"
aws iam attach-user-policy \
    --user-name $USER_NAME \
    --policy-arn $POLICY_ARN \
    --profile $AWS_PROFILE

# Also attach the EKS describe policy for kubectl access
aws iam attach-user-policy \
    --user-name $USER_NAME \
    --policy-arn arn:aws:iam::aws:policy/AmazonEKSClusterPolicy \
    --profile $AWS_PROFILE 2>/dev/null || true

# Create access key for the user
echo -e "${GREEN}Creating access key...${NC}"

# Check if user already has access keys
EXISTING_KEYS=$(aws iam list-access-keys --user-name $USER_NAME --query 'AccessKeyMetadata[].AccessKeyId' --output text --profile $AWS_PROFILE)
if [ -n "$EXISTING_KEYS" ]; then
    echo -e "${YELLOW}User already has access keys. Creating new one...${NC}"
fi

# Create new access key
ACCESS_KEY_OUTPUT=$(aws iam create-access-key --user-name $USER_NAME --profile $AWS_PROFILE)
ACCESS_KEY_ID=$(echo $ACCESS_KEY_OUTPUT | jq -r '.AccessKey.AccessKeyId')
SECRET_ACCESS_KEY=$(echo $ACCESS_KEY_OUTPUT | jq -r '.AccessKey.SecretAccessKey')

# Save credentials to a secure file
CREDS_FILE="github-actions-aws-credentials.txt"
cat > $CREDS_FILE << EOF
GitHub Actions AWS Credentials for SAML Tools
Generated on: $(date)

AWS_ACCESS_KEY_ID=${ACCESS_KEY_ID}
AWS_SECRET_ACCESS_KEY=${SECRET_ACCESS_KEY}

These credentials have permissions to:
- Push/pull images to/from ECR
- Describe EKS cluster for kubectl access
- Limited to saml-tools-cluster in ${AWS_REGION}

IMPORTANT: 
1. Add these as secrets in your GitHub repository
2. Delete this file after adding to GitHub
3. Keep these credentials secure!
EOF

chmod 600 $CREDS_FILE

# Update kubeconfig to allow the GitHub Actions user
echo -e "${GREEN}Updating EKS cluster to allow GitHub Actions user...${NC}"

# Get the current aws-auth ConfigMap
kubectl get configmap aws-auth -n kube-system -o yaml > /tmp/aws-auth.yaml

# Check if the user is already in the configmap
if grep -q "$USER_NAME" /tmp/aws-auth.yaml; then
    echo -e "${YELLOW}User already has access to EKS cluster${NC}"
else
    echo -e "${GREEN}Adding user to EKS aws-auth ConfigMap...${NC}"
    
    # Create the new mapUsers entry
    cat > /tmp/aws-auth-patch.yaml << EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapUsers: |
    - userarn: arn:aws:iam::${AWS_ACCOUNT_ID}:user/${USER_NAME}
      username: ${USER_NAME}
      groups:
        - system:masters
EOF
    
    # Apply the patch
    kubectl patch configmap/aws-auth -n kube-system --patch "$(cat /tmp/aws-auth-patch.yaml)"
fi

# Clean up temporary files
rm -f /tmp/github-actions-policy.json /tmp/aws-auth.yaml /tmp/aws-auth-patch.yaml

echo -e "${GREEN}✅ AWS resources created successfully!${NC}"
echo ""
echo -e "${YELLOW}NEXT STEPS:${NC}"
echo "1. The credentials have been saved to: ${CREDS_FILE}"
echo ""
echo "2. Add these as GitHub Secrets:"
echo "   - Go to: https://github.com/${GITHUB_REPO}/settings/secrets/actions"
echo "   - Click 'New repository secret'"
echo "   - Add the following secrets:"
echo "     • Name: AWS_ACCESS_KEY_ID"
echo "       Value: ${ACCESS_KEY_ID}"
echo "     • Name: AWS_SECRET_ACCESS_KEY"
echo "       Value: [from ${CREDS_FILE}]"
echo ""
echo "3. (Optional) Add Slack webhook for notifications:"
echo "   • Name: SLACK_WEBHOOK"
echo "   • Value: Your Slack webhook URL"
echo ""
echo -e "${RED}4. IMPORTANT: Delete ${CREDS_FILE} after adding to GitHub!${NC}"
echo ""
echo "5. Test the deployment:"
echo "   - Push to main branch or"
echo "   - Go to Actions tab and manually trigger 'Deploy to AWS EKS' workflow"