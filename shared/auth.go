// Package shared provides AWS session management and attack playbook utilities
// for CloudGoat scenario scripts.
//
// Auth usage:
//
//	// Static credentials from start.txt (most CloudGoat scenarios)
//	cfg, err := shared.GetConfig(ctx, shared.AuthOptions{
//	    Region:          "us-east-1",
//	    AccessKeyID:     cfgMap.MustGet("aws_access_key_id"),
//	    SecretAccessKey: cfgMap.MustGet("aws_secret_access_key"),
//	})
//
//	// Ambient credentials (pre-assumed via assume-aws shell function)
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
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AuthOptions controls how GetConfig resolves AWS credentials.
type AuthOptions struct {
	// Region is the AWS region for all API calls. Required.
	Region string

	// AccessKeyID and SecretAccessKey are static credentials read directly
	// from CloudGoat's start.txt. When both are set, they take precedence
	// over Profile and ambient credentials. Never hardcode these — always
	// read them from start.txt via LoadStart() at runtime.
	AccessKeyID     string
	SecretAccessKey string

	// RoleARN is the ARN of the role to assume via STS AssumeRole.
	// If set, GetConfig assumes this role using whatever source credentials
	// are resolved (static, profile, or ambient). If empty, the resolved
	// source credentials are returned directly.
	RoleARN string

	// SessionName is the RoleSessionName passed to STS. Appears in
	// CloudTrail. Defaults to "cloudgoat-playbook" if empty.
	SessionName string

	// Profile is the named AWS credentials profile to use as the source
	// identity. Ignored if AccessKeyID/SecretAccessKey are set.
	Profile string
}

// GetConfig returns an aws.Config for the given options.
//
// Credential resolution order:
//  1. Static credentials (AccessKeyID + SecretAccessKey) — used when
//     CloudGoat start.txt provides raw AKID/secret with no role to assume.
//  2. Named profile (Profile) — used as the source identity for assume-role.
//  3. Ambient credentials (env vars, ~/.aws/credentials, instance profile).
//
// If RoleARN is set, the resolved source credentials are used to call
// STS AssumeRole and the returned config uses the resulting session credentials.
func GetConfig(ctx context.Context, opts AuthOptions) (aws.Config, error) {
	if opts.SessionName == "" {
		opts.SessionName = "cloudgoat-playbook"
	}

	// Build source config load options
	loadOpts := []func(*config.LoadOptions) error{
		config.WithRegion(opts.Region),
	}

	// Static credentials take precedence over profile and ambient
	if opts.AccessKeyID != "" && opts.SecretAccessKey != "" {
		loadOpts = append(loadOpts,
			config.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(
					opts.AccessKeyID,
					opts.SecretAccessKey,
					"", // no session token for long-lived user creds
				),
			),
		)
	} else if opts.Profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(opts.Profile))
	}

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

