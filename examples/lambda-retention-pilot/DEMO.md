# The demo: a Lambda deploy, gated

A run of show for the pilot, built for a laptop that executes the pilot's pipeline file
locally (WALKTHROUGH.md, 5E). Four acts, one command each, about fifteen minutes with
talk. The story in one sentence: the same pipeline file, in four commits, goes from
letting a misconfiguration ship to blocking it, to blocking it on exactly one rule, to
letting the fixed change through.

`demo/act1.sh` to `demo/act4.sh` put the repository into each act's state and commit it,
so nothing is edited by hand. `demo/run.sh` executes the pipeline file, test stage only
unless given `--deploy`.

## Before the demo

Thirty minutes is enough. In order:

1. **Sign in.**
   ```sh
   aws sso login --profile <sandbox profile>
   aws sts get-caller-identity --profile <sandbox profile>
   ```
2. **One terminal in the pilot repository, with the environment.** This is the terminal
   the audience sees; make the font large before the run-through.
   ```sh
   cd ~/lambda-retention-pilot
   source ~/gate-venv/bin/activate
   export AWS_PROFILE=<sandbox profile>
   export FALCON_CLIENT_ID=... FALCON_CLIENT_SECRET=...
   export PILOT_PROJECT_ID=<the number on the pilot project's page> GITLAB_USER=<your gitlab username>
   read -rs -p "GitLab token: " GL_TOKEN; echo; export GL_TOKEN
   ```
3. **Reset to act one and run it once.** It caches the Terraform providers, proves the
   token, the scan and the state, and leaves the board on screen.
   ```sh
   demo/act1.sh && demo/run.sh
   ```
   Expected: `PASS plan`, `PASS fcs-deploy-gate`, and the gate's log ending in the
   two Findings with the advisory warning.
4. **The console half, if you want it.** The IOM exists only if the log group was
   deployed without retention. From act one, `demo/run.sh --deploy` creates the four
   resources; the IOM shows after the console's next assessment, at the cadence you
   recorded. If the demo is too soon for that, skip it and tell the IOM part in words.
5. **Browser tabs**, left to right: the pilot project on GitLab, open on the commit
   list; the console's IaC scan view, searched for the pilot project's full path; the
   posture view for the sandbox account, searched for `fcs-gate-pilot`.
6. **Clear the terminal.** `clear`, then `git log --oneline -3` as the opening screen.

## Run of show

Every run takes about half a minute: plan and the gate in parallel, then the board.

### Opening, one minute

Show the pipeline file and the commit list. Say: this is the project's own
`.gitlab-ci.yml`. It plans, runs the Gate beside the plan, and applies only when the
Gate's job passes. The Gate is a Python package that runs the Falcon Cloud Security
CLI's IaC scan and turns the result into a Verdict. The platform's runner assignment is
pending, so a local executor runs this same file on the laptop; the include, the Gate,
the scan upload and the Terraform state are all the real ones.

### Act one: today's world, three minutes

```sh
demo/act1.sh && demo/run.sh
```

Show: the board, `PASS plan` and `PASS fcs-deploy-gate`; the gate's summary, two
Blocking Findings on the log group, medium and informational, and the line "Advisory
mode: the Verdict is blocked but the Deployment proceeds".

Say: the Gate saw both problems before anything was applied. In advisory mode it only
reports, and the apply job would run. That is the deploy we do today, with the finding
arriving in the console afterwards as an IOM. Switch to the console: the scan is listed
under the project's path, with the same two Findings. If the gap was deployed, the
posture tab shows the IOM on the log group: this is what the next three acts prevent.

### Act two: the Gate enforces, two minutes

```sh
demo/act2.sh && demo/run.sh
```

Show: `git log --oneline -1`, the commit changed one word in the pipeline file;
`FAIL fcs-deploy-gate`, and no apply line on the board.

Say: one setting, advisory to enforcing. The same two Findings now fail the job, and
apply never starts because it needs the gate's job. Nothing reached the account. Point
out the Blocking threshold line in the summary: by default the Gate blocks on critical,
high and medium; this pilot includes informational because the retention rule is
informational in the scanner, and that threshold is per repository.

### Act three: one rule, three minutes

```sh
demo/act3.sh && demo/run.sh
```

Show: `cat .fcs-gate.yml`; the board still `FAIL fcs-deploy-gate`; the summary with one
Blocking Finding, retention, and the Excluded section naming the KMS Finding with its
reason, approver and expiry.

Say: the KMS finding is real but outside this pilot, so the Security team approved an
Exclusion. It lives in the repository, next to the code, reviewed like code; it names
who approved it and when it expires, and an Exclusion that no longer matches anything
is reported as stale. There is no bypass input anywhere else. What is left is the one
rule this pilot is about: a Lambda log group that would keep logs forever.

### Act four: the fix, three minutes

```sh
demo/act4.sh && demo/run.sh --deploy
```

Show: `git show --stat HEAD`, one line added to `main.tf`; the board, three PASS
lines; the apply output.

Say: thirty days of retention, one line. The Verdict is clear, the gate's job passes,
and apply runs for the first time through the Gate. If the gap was deployed earlier,
apply changes one attribute and the IOM closes on the next assessment; otherwise the
four resources are created already compliant and no IOM ever appears. Either way, the
console's scan list now has one scan per act. Without `--deploy`, the same command shows
the clear Verdict and stops before apply.

### Close, one minute

What this was: one rule, one function, four commits, the real scanner and the real
console. What comes next: the same pipeline on the platform's runners when one is
granted, with the Falcon client as masked variables and AWS through OIDC instead of a
laptop session; the Change-aware scope for the existing estate, where only Findings new
since the Baseline block, so the backlog does not stop every deploy; the GitHub adapter,
the same core, for the new estate; and the mapping from IaC rules to IOM policies, so a
clear Verdict can be read as "no IOM", which today it is not.

## Likely questions

- **Does a clear Verdict mean no IOM?** No, and the summary says so on every run. IaC
  rules and IOM policies are two rule sets; measuring the overlap is the next piece of
  work.
- **Why block on an informational finding?** Because this rule is informational in the
  scanner and the pilot is about this rule. The threshold is set per repository, and
  the default blocks on critical, high and medium.
- **Who approves an Exclusion?** The Security team. The file needs an approver and an
  expiry, and it is reviewed with the code that carries it.
- **Can a developer turn it off?** Not from the pipeline: there is no bypass input, and
  apply needs the gate's job. Advisory mode is a repository setting, visible in the
  file and in the commit history.
- **Where are the credentials?** The Falcon client id and secret reach the Gate as
  environment variables, masked variables on a real runner; nothing is written to the
  repository, and the token is redacted from anything the Gate quotes. Today's run
  used the laptop's own AWS session.
- **How much time does it add?** About fifteen seconds for this module, most of it the
  pinned CLI download, which is checksum-verified on every run.
- **What about findings we already have?** Change-aware scope: the Gate scans the
  Baseline too and blocks only on what the change introduces. Whole-tree, used here,
  blocks on everything at or above the threshold.
- **Why is there no pipeline in GitLab?** The project has no runner yet. Each push does
  create a pipeline there, and it waits; the laptop executed the same file.

## If something goes wrong during the demo

| What you see | Do |
|---|---|
| Gate job: "token" or "401" from the Falcon API | The client secret in the shell is wrong or expired; re-export it |
| Plan: "token has expired" or "no valid credential sources" | `aws sso login --profile <sandbox profile>`, run again |
| Plan: "Error acquiring the state lock", `Lock Info` with an id | `cd lambda && terraform force-unlock <id> && cd ..`, run again |
| Plan: lock error with 404 | `PILOT_PROJECT_ID` is not the number; fix the export |
| Gate job: "destination path already exists" | Stale template cached; `demo/run.sh --fetch-includes` |
| Summary lists "IAM Access Analyzer Not Enabled" at act three | `DEMO_EXCLUDE_ACCESS_ANALYZER=1 demo/act3.sh && demo/run.sh` |
| Anything else in the gate job | The summary quotes the CLI's last lines; read them aloud, run again |

A second run of any act is identical to the first; nothing in the four acts is a
one-shot.

## After the demo

```sh
cd ~/lambda-retention-pilot/lambda && terraform destroy && cd ..
rm -rf lambda/.terraform
```

The first command removes the four resources using the state the runs used. The second
removes the backend settings Terraform saved on the laptop, token included. Then revoke
the token in GitLab, and bring back what ticket #9 and #10 want: the raw report from
`fcs-gate/`, sanitised; the console menu paths; the IOM policy's name, Severity and
resource type; and the assessment cadence.
