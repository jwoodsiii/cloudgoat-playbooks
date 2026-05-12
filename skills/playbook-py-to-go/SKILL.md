---
name: playbook-py-to-go
description: >
  Converts a tested CloudGoat Python attack playbook into an idiomatic Go
  attack script. Use this skill whenever the user wants to "rewrite the
  attack in Go", "build the Go version", "port attack.py to attack.go", or
  "create the Go artifact for this scenario". Reads the scenario README as
  the primary source for attack structure and uses attack.py as a reference
  for exact API calls and response fields. Always use this skill in the
  cloudgoat-playbooks repo for Go conversions — it encodes the SDK v2
  pagination patterns, error handling conventions, and shared package
  imports specific to this repo.
---

# playbook-py-to-go

Converts a tested CloudGoat scenario from Python to idiomatic Go.

## Inputs

The user provides a scenario name. The skill reads:
1. `scenarios/<scenario>/README.md` — primary source for attack structure and intent
2. `scenarios/<scenario>/attack.py` — reference for exact API calls and field names
3. `shared/auth.go` and `shared/utils.go` — must use these, do not rewrite

## Output

A single file: `scenarios/<scenario>/attack.go`

## Hard preconditions

Before generating anything, verify:
1. `scenarios/<scenario>/README.md` exists
2. `scenarios/<scenario>/attack.py` exists
3. `scenarios/<scenario>/findings.json` exists (proves attack.py ran successfully)

If any are missing, stop and tell the user. The Go version is a maturation
step — it requires a tested Python version to translate from. Do not generate
attack.go from README alone.

---

## Step 1 — Read inputs

Read the README first to understand the attack structure and intent.
Read attack.py second to extract:
- Exact SDK API calls being made
- Response field names being read
- Order of operations
- Error handling decisions (which failures are fatal)

Do not read attack.py first — that biases the generated Go toward Python
patterns instead of idiomatic Go.

---

## Step 2 — Map Python patterns to Go

| Python | Go (SDK v2) |
|---|---|
| `boto3.client("iam")` | `iam.NewFromConfig(cfg)` |
| `client.list_attached_user_policies(UserName=u)` | `client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: &u})` |
| `resp["AttachedPolicies"]` | `resp.AttachedPolicies` (typed `[]types.AttachedPolicy`) |
| `try: ... except Exception as e:` | `if err != nil { ... }` |
| `iam.get_paginator("list_roles")` | `iam.NewListRolesPaginator(client, &iam.ListRolesInput{})` |
| `for page in paginator.paginate():` | `for paginator.HasMorePages() { page, err := paginator.NextPage(ctx); ... }` |
| `json.loads(s)` | `json.Unmarshal([]byte(s), &target)` |
| `info(f"text {var}")` | `shared.Info(fmt.Sprintf("text %v", var))` |
| `error(msg, fatal=True)` | `shared.Error(msg, true)` |

For full reference on SDK v2 patterns including paginators and string pointer
helpers, read `references/sdk-v2-patterns.md`.

---

## Step 3 — Generate `attack.go`

### Required structure

```go
// Package main provides the <scenario_title> CloudGoat attack playbook.
//
// <one-paragraph summary from README>
//
// Attack path:
//   1. <step heading>
//   2. <step heading>
//   ...
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
    "strings"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/service/iam"
    "github.com/aws/aws-sdk-go-v2/service/sts"

    "github.com/jwoodsiii/cloudgoat-playbooks/shared"
)
```

### Required main function pattern

```go
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
        Region:  *region,
        RoleARN: *roleARN,
        AccessKeyID: cfgMap.MustGet("aws_access_key_id"),
        SecretAccessKey: cfgMap.MustGet("aws_secret_access_key"),
    })
    if err != nil {
        shared.Error(fmt.Sprintf("building AWS config: %v", err), true)
    }

    // Resolve identity from STS, never trust start.txt for username
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

    // ... attack steps ...

    if err := shared.WriteFindings(findings, "<scenario>", "findings.json"); err != nil {
        shared.Error(fmt.Sprintf("writing findings: %v", err), false)
    }

    _ = cfgMap // keep reference even if unused in this scenario
}
```

### Per-step pattern

Each attack step becomes a labeled section, structurally matching the
Python script's step boundaries:

```go
// --- Step 1: <heading from README> ---
shared.Step("<heading from README>")
{
    paginator := iam.NewListAttachedUserPoliciesPaginator(iamClient,
        &iam.ListAttachedUserPoliciesInput{UserName: &username})

    var attached []types.AttachedPolicy
    for paginator.HasMorePages() {
        page, err := paginator.NextPage(ctx)
        if err != nil {
            shared.Error(fmt.Sprintf("list_attached_user_policies: %v", err), true)
            break
        }
        attached = append(attached, page.AttachedPolicies...)
    }

    // ... process attached, append findings ...
}
```

Use anonymous blocks (`{ ... }`) to scope per-step variables. This mirrors
the Python step boundaries and prevents variable bleed between steps.

---

## Step 4 — Idiomatic Go decisions

### Where to add value beyond mechanical translation

1. **Concurrent steps** — if two attack steps are independent (e.g. enumerating
   group memberships and listing all roles, which don't depend on each other),
   note the opportunity to use `errgroup.Group` but do not implement it unless
   the user explicitly asks. The default is sequential to keep diffs minimal.

2. **Pointer helpers** — use `aws.String("foo")` for input pointers and
   `aws.ToString(out.Field)` for output pointers. Never dereference raw pointers
   without nil checks.

3. **Typed responses** — `types.AttachedPolicy.PolicyArn` is `*string`. Always
   dereference via `aws.ToString` to handle nil safely.

4. **Error handling philosophy** — match Python's intent: `shared.Error(msg, true)`
   for genuine fatal errors (cannot continue without this data), `shared.Error(msg, false)`
   for skippable failures. Never use `panic()`. Never bare-return without logging.

### What NOT to do

- Do not introduce dependencies beyond `aws-sdk-go-v2` and stdlib
- Do not use `cobra` or `viper` — `flag` stdlib only per AGENTS.md
- Do not add structured logging libraries — `shared.Info`/`Step`/`Finding` are the
  only output helpers
- Do not reorder attack steps for "optimization" — preserve the README's narrative order
- Do not silently swallow errors — every error path either fatally exits or logs

---

## Step 5 — Validate

After writing `attack.go`, instruct the user to run:

```bash
cd scenarios/<scenario>/
go build -o /tmp/attack attack.go
```

If the build fails, fix and re-validate before declaring done.

If the user has the scenario still deployed, also instruct them to run:

```bash
./attack --start-file ./start.txt --region us-east-1
diff findings.json findings.go.json   # or visual compare
```

The Go findings.json should contain the same number of findings as the
Python version, covering the same flags and resources.

---

## Step 6 — Update the scenario README

Append a one-line note under the Summary section:

```markdown
**Implementations:** Python (`attack.py`) — primary; Go (`attack.go`) — final artifact.
```

Do not modify any other section of the README. The narrative belongs to the
attack itself, not the implementation language.

---

## Reference files

- `references/sdk-v2-patterns.md` — SDK v2 idioms (paginators, pointer helpers,
  typed responses, context handling). Read before generating any SDK call.

---

## Off-limits paths

- Do not touch `shared/` — only consume from it
- Do not touch `attack.py` — it is the reference, not the target
- Do not touch any directory outside `scenarios/<scenario>/`
- The only file written is `scenarios/<scenario>/attack.go`
- The only file modified is `scenarios/<scenario>/README.md` (one line append only)
