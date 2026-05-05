// Package shared provides AWS session management and attack playbook utilities
// for CloudGoat scenario scripts.
//
// Auth usage:
//
//	// Local env aws credentials
//	cfg, err := shared.GetConfig(ctx, shared.AuthOptions{Region: "us-east-1"})
//
//	// Explicit assume-role from ambient source identity
//	cfg, err := shared.GetConfig(ctx, shared.AuthOptions{
//	    Region:      "us-east-1",
//	    RoleARN:     "arn:aws:iam::123456789012:role/target-role",
//	    SessionName: "cloudgoat-playbook",
//	})
package shared

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AuthOptions controls how GetConfig resolves AWS credentials.
type AuthOptions struct {
	// Region is the AWS region for all API calls. Required.
	Region string

	// RoleARN is the ARN of the role to assume via STS AssumeRole.
	// If empty, ambient credentials are used (env vars, ~/.aws/credentials,
	// or instance profile) — useful when you've pre-assumed a role via the
	// assume-aws shell function.
	RoleARN string

	// SessionName is the RoleSessionName passed to STS. Appears in
	// CloudTrail. Defaults to "cloudgoat-playbook" if empty.
	SessionName string

	// Profile is the named AWS credentials profile to use as the source
	// identity for the assume-role call. Ignored if RoleARN is empty.
	Profile string
}

// GetConfig returns an aws.Config for the given options.
//
// If opts.RoleARN is set, GetConfig assumes that role via STS and returns a
// config using the resulting short-lived credentials. The source identity is
// either opts.Profile (if set) or ambient credentials.
//
// If opts.RoleARN is empty, GetConfig returns a config using ambient
// credentials directly.
func GetConfig(ctx context.Context, opts AuthOptions) (aws.Config, error) {
	if opts.SessionName == "" {
		opts.SessionName = "cloudgoat-playbook"
	}

	// Build load options common to both paths
	loadOpts := []func(*config.LoadOptions) error{
		config.WithRegion(opts.Region),
	}
	if opts.Profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(opts.Profile))
	}

	// Load source config (ambient or named profile)
	sourceCfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("loading source AWS config: %w", err)
	}

	if opts.RoleARN == "" {
		// No assume-role — return source config directly
		return sourceCfg, nil
	}

	// Assume the target role using the source config as the caller identity
	stsClient := sts.NewFromConfig(sourceCfg)
	assumeRoleProvider := stscreds.NewAssumeRoleProvider(stsClient, opts.RoleARN,
		func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = opts.SessionName
		},
	)

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(opts.Region),
		config.WithCredentialsProvider(assumeRoleProvider),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("building config for assumed role %s: %w", opts.RoleARN, err)
	}

	return cfg, nil
}
