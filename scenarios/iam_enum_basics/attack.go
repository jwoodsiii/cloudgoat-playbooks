// Package main provides the aws_iam_enumeration CloudGoat attack playbook.
//
// Basic IAM user permissions enumeration. Given an AKID, answers the question:
// what can this user do? Maps managed/inline policies, group memberships, and
// assumable roles to uncover five hidden flags.
//
// Attack path:
//
//  1. Attached policies (managed) — list managed policies; flag in description
//  2. Inline policies — read inline policy documents; flag in document body
//  3. Group permissions — discover group memberships; flag in group metadata
//  4. Assumable roles — scan all roles for flag4 target; flag in role details
//  5. Managed policy deep dive — pull versioned policy document; flag in JSON
//
// Usage:
//
//	go run attack.go --start-file ./start.txt [--region us-east-1]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/jwoodsiii/cloudgoat-playbooks/shared"
)

// containsFlag includes bare "HSM" because Flag 2 (HSM1nl1n3p0l1cyd1sc0v3r3d)
// uses no delimiter — the three-prefix form would miss it.
func containsFlag(s string) bool {
	return strings.Contains(s, "HSM{") ||
		strings.Contains(s, "HSM-") ||
		strings.Contains(s, "HSM_") ||
		strings.Contains(s, "HSM")
}

type policyDoc struct {
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Resource interface{} `json:"Resource"`
}

func extractStrings(v interface{}) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []interface{}:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func main() {
	startFile := flag.String("start-file", "./start.txt", "path to CloudGoat start.txt")
	region := flag.String("region", "us-east-1", "AWS region")
	roleARN := flag.String("role-arn", "", "optional role ARN to assume")
	flag.Parse()

	ctx := context.Background()

	cfgMap, err := shared.LoadStart(*startFile)
	if err != nil {
		shared.Error(fmt.Sprintf("loading start.txt: %v", err), true)
	}

	awsCfg, err := shared.GetConfig(ctx, shared.AuthOptions{
		Region:          *region,
		RoleARN:         *roleARN,
		AccessKeyID:     cfgMap.MustGet("aws_access_key_id"),
		SecretAccessKey: cfgMap.MustGet("aws_secret_access_key"),
	})
	if err != nil {
		shared.Error(fmt.Sprintf("building AWS config: %v", err), true)
	}

	stsClient := sts.NewFromConfig(awsCfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		shared.Error(fmt.Sprintf("get-caller-identity: %v", err), true)
	}
	arn := aws.ToString(identity.Arn)
	parts := strings.Split(arn, "/")
	username := parts[len(parts)-1]
	shared.Info(fmt.Sprintf("Running as: %s", arn))

	iamClient := iam.NewFromConfig(awsCfg)
	var findings []shared.FindingEntry

	var managedPolicyArn string
	var managedPolicyVersion string

	// --- Step 1: Attached policies (managed) ---
	shared.Step("Attached policies (managed)")
	{
		paginator := iam.NewListAttachedUserPoliciesPaginator(iamClient,
			&iam.ListAttachedUserPoliciesInput{UserName: &username})

		var attached []iamtypes.AttachedPolicy
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				shared.Error(fmt.Sprintf("list_attached_user_policies: %v", err), true)
				break
			}
			attached = append(attached, page.AttachedPolicies...)
		}

		shared.Info(fmt.Sprintf("Found %d attached managed policy/policies", len(attached)))
		for _, policy := range attached {
			policyArn := aws.ToString(policy.PolicyArn)
			shared.Info(fmt.Sprintf("Policy: %s  ARN: %s", aws.ToString(policy.PolicyName), policyArn))

			out, err := iamClient.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: policy.PolicyArn})
			if err != nil {
				shared.Error(fmt.Sprintf("get_policy(%s): %v", policyArn, err), false)
				continue
			}
			desc := aws.ToString(out.Policy.Description)
			path := aws.ToString(out.Policy.Path)
			shared.Info(fmt.Sprintf("  Description: %q  Path: %q", desc, path))

			for _, pair := range [][2]string{{"description", desc}, {"path", path}} {
				if containsFlag(pair[1]) {
					shared.Finding(fmt.Sprintf("Flag1 in policy %s: %s", pair[0], pair[1]))
					findings = append(findings, shared.FindingEntry{
						Title:    "Attached managed policy — metadata field",
						Detail:   fmt.Sprintf("Policy %s field contains flag: %s", pair[0], pair[1]),
						Resource: policyArn,
						Severity: "low",
					})
				}
			}

			if !strings.HasPrefix(policyArn, "arn:aws:iam::aws:") {
				managedPolicyArn = policyArn
				managedPolicyVersion = aws.ToString(out.Policy.DefaultVersionId)
				if managedPolicyVersion == "" {
					managedPolicyVersion = "v1"
				}
			}
		}
	}

	// --- Step 2: Inline policies ---
	shared.Step("Inline policies")
	{
		paginator := iam.NewListUserPoliciesPaginator(iamClient,
			&iam.ListUserPoliciesInput{UserName: &username})

		var policyNames []string
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				shared.Error(fmt.Sprintf("list_user_policies: %v", err), false)
				break
			}
			policyNames = append(policyNames, page.PolicyNames...)
		}

		shared.Info(fmt.Sprintf("Found %d inline policy/policies: %v", len(policyNames), policyNames))
		for _, name := range policyNames {
			out, err := iamClient.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
				UserName:   &username,
				PolicyName: aws.String(name),
			})
			if err != nil {
				shared.Error(fmt.Sprintf("get_user_policy(%s): %v", name, err), false)
				continue
			}
			decoded, err := url.QueryUnescape(aws.ToString(out.PolicyDocument))
			if err != nil {
				shared.Error(fmt.Sprintf("url-decode policy doc (%s): %v", name, err), false)
				continue
			}
			preview := decoded
			if len(preview) > 300 {
				preview = preview[:300]
			}
			shared.Info(fmt.Sprintf("  %s: %s", name, preview))
			if containsFlag(decoded) {
				shared.Finding(fmt.Sprintf("Flag2 in inline policy document (%s): %s", name, decoded))
				findings = append(findings, shared.FindingEntry{
					Title:    "Inline policy — policy document",
					Detail:   fmt.Sprintf("Inline policy document for %s contains a flag", name),
					Resource: fmt.Sprintf("user/%s/policy/%s", username, name),
					Severity: "low",
				})
			}
		}
	}

	// --- Step 3: Group permissions ---
	shared.Step("Group permissions")
	{
		paginator := iam.NewListGroupsForUserPaginator(iamClient,
			&iam.ListGroupsForUserInput{UserName: &username})

		var groups []iamtypes.Group
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				shared.Error(fmt.Sprintf("list_groups_for_user: %v", err), false)
				break
			}
			groups = append(groups, page.Groups...)
		}

		shared.Info(fmt.Sprintf("Found %d group(s)", len(groups)))
		for _, group := range groups {
			gname := aws.ToString(group.GroupName)
			gpath := aws.ToString(group.Path)
			shared.Info(fmt.Sprintf("  Group: %s  Path: %q  ARN: %s", gname, gpath, aws.ToString(group.Arn)))

			for _, pair := range [][2]string{{"name", gname}, {"path", gpath}} {
				if containsFlag(pair[1]) {
					shared.Finding(fmt.Sprintf("Flag3 in group %s: %s", pair[0], pair[1]))
					findings = append(findings, shared.FindingEntry{
						Title:    "Group membership — group metadata",
						Detail:   fmt.Sprintf("Group %s field contains flag: %s", pair[0], pair[1]),
						Resource: aws.ToString(group.Arn),
						Severity: "low",
					})
				}
			}

			inlineOut, err := iamClient.ListGroupPolicies(ctx, &iam.ListGroupPoliciesInput{GroupName: &gname})
			if err != nil {
				shared.Error(fmt.Sprintf("list_group_policies(%s): %v", gname, err), false)
			} else {
				shared.Info(fmt.Sprintf("  Group inline policies: %v", inlineOut.PolicyNames))
			}
			attachedOut, err := iamClient.ListAttachedGroupPolicies(ctx, &iam.ListAttachedGroupPoliciesInput{GroupName: &gname})
			if err != nil {
				shared.Error(fmt.Sprintf("list_attached_group_policies(%s): %v", gname, err), false)
			} else {
				names := make([]string, len(attachedOut.AttachedPolicies))
				for i, p := range attachedOut.AttachedPolicies {
					names[i] = aws.ToString(p.PolicyName)
				}
				shared.Info(fmt.Sprintf("  Group attached policies: %v", names))
			}
		}
	}

	// --- Step 4: Assumable roles ---
	shared.Step("Assumable roles")
	{
		paginator := iam.NewListRolesPaginator(iamClient, &iam.ListRolesInput{})

		var roles []iamtypes.Role
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				shared.Error(fmt.Sprintf("list_roles: %v", err), true)
				break
			}
			roles = append(roles, page.Roles...)
		}

		shared.Info(fmt.Sprintf("Total roles in account: %d", len(roles)))
		for _, role := range roles {
			rname := aws.ToString(role.RoleName)
			shared.Info(fmt.Sprintf("Target role: %s ARN: %s", rname, aws.ToString(role.Arn)))

			tagsOut, err := iamClient.ListRoleTags(ctx, &iam.ListRoleTagsInput{RoleName: &rname})
			if err != nil {
				shared.Error(fmt.Sprintf("list_role_tags(%s): %v", rname, err), false)
				continue
			}
			for _, tag := range tagsOut.Tags {
				tagStr := fmt.Sprintf("%s=%s", aws.ToString(tag.Key), aws.ToString(tag.Value))
				shared.Info(fmt.Sprintf("  Tag: %s", tagStr))
				if containsFlag(tagStr) {
					shared.Finding(fmt.Sprintf("Flag4 in role tag: %s", tagStr))
					findings = append(findings, shared.FindingEntry{
						Title:    "Assumable role — role tag",
						Detail:   fmt.Sprintf("Role tag contains flag: %s", tagStr),
						Resource: aws.ToString(role.Arn),
						Severity: "low",
					})
				}
			}
		}
	}

	// --- Step 5: Managed policy deep dive (versioned document) ---
	shared.Step("Managed policy deep dive (versioned document)")
	{
		if managedPolicyArn == "" {
			shared.Error("No managed policy ARN from step 1 — skipping", false)
		} else {
			out, err := iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: &managedPolicyArn,
				VersionId: &managedPolicyVersion,
			})
			if err != nil {
				shared.Error(fmt.Sprintf("get_policy_version: %v", err), false)
			} else {
				decoded, err := url.QueryUnescape(aws.ToString(out.PolicyVersion.Document))
				if err != nil {
					shared.Error(fmt.Sprintf("url-decode policy version doc: %v", err), false)
				} else {
					shared.Info(fmt.Sprintf("Policy version %s document:\n%s", managedPolicyVersion, decoded))
					var doc policyDoc
					if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
						shared.Error(fmt.Sprintf("parse policy version doc: %v", err), false)
					} else {
						for _, stmt := range doc.Statement {
							for _, resource := range extractStrings(stmt.Resource) {
								if containsFlag(resource) {
									shared.Finding(fmt.Sprintf("Flag5 in policy Resource field: %s", resource))
									findings = append(findings, shared.FindingEntry{
										Title:    "Managed policy version — Resource field",
										Detail:   fmt.Sprintf("Policy v%s Resource contains flag: %s", managedPolicyVersion, resource),
										Resource: managedPolicyArn,
										Severity: "low",
									})
								}
							}
						}
					}
				}
			}
		}
	}

	if err := shared.WriteFindings(findings, "iam_enum_basics", "findings.json"); err != nil {
		shared.Error(fmt.Sprintf("writing findings: %v", err), false)
	}
}
