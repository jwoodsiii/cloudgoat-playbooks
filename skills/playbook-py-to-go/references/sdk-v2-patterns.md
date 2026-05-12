# AWS SDK Go v2 Patterns

Reference for idiomatic SDK v2 usage in CloudGoat attack playbooks.
Read before generating any SDK call in attack.go.

---

## Imports

Every IAM playbook needs at minimum:

```go
import (
    "context"
    "encoding/json"
    "flag"
    "fmt"
    "strings"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/service/iam"
    iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
    "github.com/aws/aws-sdk-go-v2/service/sts"

    "github.com/jwoodsiii/cloudgoat-playbooks/shared"
)
```

Alias `iam/types` as `iamtypes` to avoid collision with the parent `iam` package
when referencing types like `iamtypes.AttachedPolicy`.

---

## Static credentials from start.txt

Most CloudGoat scenarios provide raw AKID/secret in start.txt with no role
to assume. Always read credentials from start.txt at runtime via `LoadStart`
— never hardcode them.

```go
cfgMap, err := shared.LoadStart(*startFile)
if err != nil {
    shared.Error(fmt.Sprintf("loading start.txt: %v", err), true)
}

awsCfg, err := shared.GetConfig(ctx, shared.AuthOptions{
    Region:          *region,
    RoleARN:         *roleARN, // empty string is safe — GetConfig skips assume-role
    AccessKeyID:     cfgMap.MustGet("aws_access_key_id"),
    SecretAccessKey: cfgMap.MustGet("aws_secret_access_key"),
})
if err != nil {
    shared.Error(fmt.Sprintf("building AWS config: %v", err), true)
}
```

`GetConfig` credential resolution order:
1. `AccessKeyID` + `SecretAccessKey` if both non-empty — covers start.txt scenarios
2. Named `Profile` if set — covers pre-assumed shell sessions
3. Ambient credentials (env vars, `~/.aws/credentials`) — fallback

If `RoleARN` is also set, `GetConfig` uses whichever source credentials resolved
above to call STS AssumeRole and returns the resulting session config. Passing
an empty `RoleARN` is safe — the assume-role step is skipped entirely.

`MustGet` exits with a clear error message if the key is absent from start.txt.
Use it for credentials and other values the script cannot proceed without.
Use `cfgMap.Get(key)` (returns `string, bool`) for optional values.

---

## Pointer helpers

SDK v2 uses `*string`, `*int32`, etc. extensively. Use the `aws` package helpers:

```go
// Setting input fields
input := &iam.GetUserInput{
    UserName: aws.String("cg-bob"),
}

// Reading output fields (nil-safe)
arn := aws.ToString(user.Arn)
description := aws.ToString(policy.Description)
maxSessionDuration := aws.ToInt32(role.MaxSessionDuration)
```

Never dereference raw `*string` with `*ptr` without a nil check — SDK responses
frequently contain nil pointers for unset fields.

---

## Paginators

SDK v2 paginators are first-class types with `HasMorePages()` and `NextPage()`:

```go
paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})

var roles []iamtypes.Role
for paginator.HasMorePages() {
    page, err := paginator.NextPage(ctx)
    if err != nil {
        return fmt.Errorf("list_roles: %w", err)
    }
    roles = append(roles, page.Roles...)
}
```

Paginators exist for every `List*` operation. Common ones:
- `NewListAttachedUserPoliciesPaginator`
- `NewListUserPoliciesPaginator`
- `NewListGroupsForUserPaginator`
- `NewListRolesPaginator`
- `NewListUsersPaginator`

---

## Non-paginated single-resource calls

```go
out, err := client.GetPolicy(ctx, &iam.GetPolicyInput{
    PolicyArn: aws.String(policyArn),
})
if err != nil {
    shared.Error(fmt.Sprintf("get_policy(%s): %v", policyArn, err), false)
    return
}
description := aws.ToString(out.Policy.Description)
```

Always pass `ctx` as the first argument. Always handle the error before
reading the response.

---

## Parsing inline JSON policy documents

IAM stores policy documents as URL-encoded JSON strings in some fields and
raw JSON in others. For tfstate-captured fields, it's already raw JSON:

```go
type PolicyDocument struct {
    Version   string      `json:"Version"`
    Statement []Statement `json:"Statement"`
}

type Statement struct {
    Effect   string      `json:"Effect"`
    Action   interface{} `json:"Action"`   // string OR []string
    Resource interface{} `json:"Resource"` // string OR []string
    Sid      string      `json:"Sid,omitempty"`
}

func parsePolicyDoc(raw string) (*PolicyDocument, error) {
    var doc PolicyDocument
    if err := json.Unmarshal([]byte(raw), &doc); err != nil {
        return nil, fmt.Errorf("unmarshal policy: %w", err)
    }
    return &doc, nil
}
```

The `interface{}` types are required because IAM allows both single-string
and array-of-string values for `Action` and `Resource`. Handle both:

```go
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
```

---

## STS GetCallerIdentity pattern

```go
stsClient := sts.NewFromConfig(awsCfg)
identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
if err != nil {
    shared.Error(fmt.Sprintf("get-caller-identity: %v", err), true)
}
arn := aws.ToString(identity.Arn)
account := aws.ToString(identity.Account)
```

Extract username from the ARN:
```go
parts := strings.Split(arn, "/")
username := parts[len(parts)-1]
```

---

## URL-decoded fields

Some IAM responses URL-encode policy documents (e.g. `GetUserPolicy` returns
the `PolicyDocument` as a URL-encoded string in the SDK):

```go
import "net/url"

decoded, err := url.QueryUnescape(aws.ToString(out.PolicyDocument))
if err != nil {
    shared.Error(fmt.Sprintf("decode policy doc: %v", err), false)
    return
}
doc, err := parsePolicyDoc(decoded)
```

Always URL-decode before JSON-unmarshalling unless the tfstate already
provides the raw form. When in doubt, attempt unmarshal first, decode if it fails.

---

## Finding emission pattern

```go
findings = append(findings, shared.FindingEntry{
    Title:    "Attached managed policy — metadata field",
    Detail:   fmt.Sprintf("Policy description contains flag: %s", description),
    Resource: policyArn,
    Severity: "low",
})
shared.Finding(fmt.Sprintf("Flag in description: %s", description))
```

Order matters: append to the findings slice first, then call `shared.Finding`
for human-visible output. This keeps the data store and the operator narration
in sync.

---

## Context handling

Every SDK call takes `context.Context` as the first arg. For attack scripts,
a single `ctx := context.Background()` in `main` is sufficient. Do not
introduce timeouts unless the user requests them — premature timeouts on
slow IAM responses cause false failures.

If you do add timeouts later:

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
```

---

## Filtering AWS-managed vs customer-managed policies

Same pattern as Python:

```go
func isAWSManaged(arn string) bool {
    return strings.HasPrefix(arn, "arn:aws:iam::aws:")
}

// In step 1, filter before tracking
for _, policy := range attached {
    policyArn := aws.ToString(policy.PolicyArn)
    if !isAWSManaged(policyArn) {
        managedPolicyArn = policyArn
        // ... fetch DefaultVersionId etc.
    }
}
```

This avoids the same bug from the Python version where `IAMReadOnlyAccess`
would clobber the customer-managed policy ARN.

---

## Flag detection helper

```go
func containsFlag(s string) bool {
    return strings.Contains(s, "HSM{") ||
        strings.Contains(s, "HSM-") ||
        strings.Contains(s, "HSM_")
}
```

Same prefixes as the Python version — `HSM` alone matches the literal word
`flag` in resource names and produces false positives.

---

## Common gotchas

1. **`types.AttachedPolicy.PolicyArn` is `*string`** — always use `aws.ToString`
2. **`json.Unmarshal` into `interface{}` returns `map[string]interface{}`** — type-assert before navigating nested fields
3. **Paginator errors abort the entire iteration** — decide whether a paginator error is fatal or skippable per step
4. **`flag.Parse()` must be called before reading flag values** — failure mode is silent (zero values)
5. **STS sessions assume-role does not refresh** — for long-running attacks, build the config once at startup; for multi-hour scripts, you'd need a credentials provider, but attack playbooks are short-lived enough that this doesn't matter
