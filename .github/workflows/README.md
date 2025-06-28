# GitHub Actions Workflows

This directory contains GitHub Actions workflows for CI/CD automation of the SAML Tools project.

## Workflows

### 1. CI/CD Pipeline (`ci-cd.yml`)

A comprehensive workflow that combines continuous integration and deployment.

Triggers on:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches
- Manual workflow dispatch with environment selection

Actions:
- **Lint**: Runs golangci-lint for code quality
- **Test**: Runs all unit tests with race detection and coverage
- **Security Scan**: Runs Trivy and gosec for vulnerability scanning
- **Build and Push**: Builds ARM64 Docker images and pushes to AWS ECR
- **Deploy**: Updates EKS deployments with new images (only on main branch)
- **Test Deployment**: Verifies service endpoints are accessible
- **Notifications**: Sends Slack notifications on completion

The workflow runs all CI steps on every push/PR, but only deploys to AWS when pushing to the main branch.

### 2. Release (`release.yml`)

Triggers on:
- Push of version tags (e.g., `v1.0.0`)

Actions:
- **Release Binaries**: Uses GoReleaser to create GitHub releases with binaries
- **Release Docker**: Pushes multi-arch Docker images to GitHub Container Registry
- **Deploy Release**: Automatically deploys the release to production
- **Release Notes**: Creates comprehensive release notes

## Required Secrets

Configure these secrets in your GitHub repository settings:

### AWS Deployment
- `AWS_ACCESS_KEY_ID`: AWS access key for ECR and EKS access
- `AWS_SECRET_ACCESS_KEY`: AWS secret key

### Notifications (Optional)
- `SLACK_WEBHOOK`: Slack webhook URL for deployment notifications

## Environment Protection

The `production` environment in the release workflow can be configured with:
- Required reviewers
- Deployment protection rules
- Environment secrets

## Local Testing

Test workflows locally using [act](https://github.com/nektos/act):

```bash
# Test build workflow
act -j build

# Test deployment with secrets
act -j deploy --secret-file .env.secrets
```

## Customization

### Changing AWS Region
Update the `AWS_REGION` environment variable in `deploy-to-aws.yml`

### Changing EKS Cluster Name
Update the `EKS_CLUSTER_NAME` environment variable in `deploy-to-aws.yml`

### Adding New Components
1. Add the new component to the matrix in build workflows
2. Create corresponding Dockerfile
3. Update deployment manifests in k8s/

## Best Practices

1. **Version Tags**: Use semantic versioning (e.g., v1.2.3)
2. **Branch Protection**: Enable branch protection rules for `main`
3. **PR Reviews**: Require reviews before merging to `main`
4. **Secrets Rotation**: Regularly rotate AWS credentials
5. **Resource Tagging**: Ensure AWS resources are properly tagged

## Troubleshooting

### Build Failures
- Check Go version compatibility
- Verify all dependencies are properly vendored
- Review golangci-lint output for code issues

### Deployment Failures
- Verify AWS credentials are valid
- Check EKS cluster is accessible
- Ensure ECR repositories exist
- Verify ingress controller is properly configured

### Release Failures
- Ensure version tag follows semantic versioning
- Check GoReleaser configuration is valid
- Verify GitHub token has required permissions