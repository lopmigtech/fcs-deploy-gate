# Pilot walkthrough: the Gate in front of a Terraform apply

This is the start-to-finish procedure for the Lambda log retention pilot on a self-managed
GitLab, with the pipeline's jobs executed by a project runner on your own laptop. It takes
you from two empty GitLab projects to a demo in four acts: Advisory, Enforcing, Exclusions,
the fix. The README in this directory explains what the pilot shows; this file is the
procedure. Budget about an hour for the setup, most of it clicking, and five minutes per
act afterwards.

Angle brackets mark the values that are yours: `<gitlab-host>` is your GitLab instance's
host name, `<group>` the group path you create the projects under.

## How the pieces fit

- The **Gate project** on GitLab is a copy of this repository. The pilot's pipeline
  includes the Gate's CI template from it, and the gate job clones it again at run time,
  with the pipeline's job token, to install the Python package.
- The **pilot project** holds the Terraform under `lambda/` and the pipeline in
  `.gitlab-ci.yml`. Its default-branch pipeline plans, runs the Gate beside the plan, and
  applies from the planfile only when the Gate's job succeeds. Terraform state lives in
  GitLab's own state storage.
- The **laptop runner** picks up the pilot project's jobs and runs them in a login bash as
  you, inside WSL. With this shell executor the `image:` lines in the pipeline are ignored,
  so the laptop itself needs git, Python and Terraform.
- The **console** receives every scan the Gate runs, under the pilot project's full path,
  and shows the IOM for the log group once the apply has created it and the next
  assessment has run.

## 0. Before you start

Have all of this in hand. Nothing below works around a missing item.

- **A Falcon CI API client**: the client id and secret the handoff created (Gate README,
  "API clients, the pin and the bounds"). The pipeline file already names the Falcon
  region. You will need the console login as well, to confirm the scan and the IOM.
- **Sandbox AWS credentials** for the GovCloud sandbox account, able to create and destroy
  an IAM role, a managed policy attachment, a Lambda function and a CloudWatch log group.
  Nothing else is created. Only ever apply in the sandbox.
- **GitLab rights**: a group where you can create projects. Creating a project runner
  needs the Maintainer role on the pilot project. If your organisation requires every
  runner to be registered by the platform team, a laptop runner is the same request you
  are already waiting on; do not go around that rule.
- **The laptop**: WSL running Fedora, with `git`, `curl`, `unzip` and a `python3` of 3.11
  or newer. Use the same interpreter you used for the handoff. The Gate clone sits at
  `~/fcs-deploy-gate` with the CLI pin filled, which `main` already has.
- **Network reach from WSL** to: the GitLab host, the Falcon API host and its pre-signed
  download host (both proven by today's laptop scans), the AWS endpoints, PyPI, the
  Terraform provider registry, `releases.hashicorp.com` and the runner download on S3.
  If WSL has to use a proxy, note the proxy variables now; step 10 needs them.

Keep one notes file open, for example `~/handoff/notes.md`, and record every menu path
you use and every value this document asks you to write down. The handoff kit and
ticket #9 want them.

## 1. Create the two GitLab projects

Both blank, both private, both with "Initialize repository with a README" **unticked**,
so that your first push lands on an empty repository.

1. New project, "Create blank project", in `<group>`, name `fcs-deploy-gate`. Its path
   becomes `<group>/fcs-deploy-gate`. Write that path down: it is the one value you will
   edit into the pilot.
2. New project, same way, name `lambda-retention-pilot`. Path `<group>/lambda-retention-pilot`.

## 2. Push the Gate to GitLab

From WSL. Pull first so the latest fixes and this file come along. Use HTTPS with your
normal GitLab credentials; the TLS anchors you installed for the laptop cover it where SSH
may be blocked.

```sh
cd ~/fcs-deploy-gate && git pull
git remote add gitlab https://<gitlab-host>/<group>/fcs-deploy-gate.git
git push gitlab main
```

No pipeline starts on the Gate project. Its own `.gitlab-ci.yml` runs only when started
from the web form, so nothing sits there waiting for a runner.

## 3. Let the pilot's jobs clone the Gate

In the **Gate** project: Settings, CI/CD, expand "Job token permissions". Under the
authorized groups and projects, add `<group>/lambda-retention-pilot`.

Without this, the gate job's clone fails with "You are not allowed to download code from
this project".

## 4. Configure the pilot project

All in the **pilot** project.

### 4a. Terraform state

Settings, General, expand "Visibility, project features, permissions". Turn on
**Infrastructure**. Save. GitLab-managed Terraform state is part of that feature; the
plan job's `terraform init` gets a 403 until it is on.

### 4b. Variables

Settings, CI/CD, expand "Variables", add each of these. Leave "Protect variable"
unticked, so a merge-request pipeline would also see them. If you tick it, every act must
be a direct push to the default branch, which is also fine for the demo.

| Variable | Visibility | Value |
|---|---|---|
| `FALCON_CLIENT_ID` | Masked | the CI client's id |
| `FALCON_CLIENT_SECRET` | Masked and hidden | the CI client's secret |
| `AWS_ACCESS_KEY_ID` | Masked | sandbox credentials |
| `AWS_SECRET_ACCESS_KEY` | Masked and hidden | sandbox credentials |
| `AWS_SESSION_TOKEN` | Masked and hidden | only if the sandbox credentials are temporary |

Everything else the pipeline needs is in `.gitlab-ci.yml` already: the Falcon region, the
scanned path, the Advisory mode, the Blocking threshold that includes informational, the
Terraform root, the state name and the AWS region.

### 4c. The runner

Settings, CI/CD, expand "Runners", "Create project runner".

- Platform: Linux.
- Tags: none, and tick **Run untagged jobs**. The pilot's jobs carry no tags.
- Description: `laptop-pilot`.
- Create. The next page shows a runner authentication token starting with `glrt-`. Copy
  it now; it is shown once. Step 5 uses it.

## 5. Set up the laptop runner

From WSL, as your own user. Nothing here needs root.

### 5a. Install the runner, a Python environment for the jobs, and Terraform

```sh
mkdir -p ~/.local/bin
curl -L --output ~/.local/bin/gitlab-runner \
  https://s3.dualstack.us-east-1.amazonaws.com/gitlab-runner-downloads/latest/binaries/gitlab-runner-linux-amd64
chmod +x ~/.local/bin/gitlab-runner
gitlab-runner --version

python3 -m venv ~/gate-venv

terraform version || {
  curl -LO https://releases.hashicorp.com/terraform/1.9.8/terraform_1.9.8_linux_amd64.zip
  unzip -d ~/.local/bin terraform_1.9.8_linux_amd64.zip
  rm terraform_1.9.8_linux_amd64.zip
}
```

If `gitlab-runner --version` says "command not found", `~/.local/bin` is not on your
PATH; run the commands below as `~/.local/bin/gitlab-runner` instead.

The venv is where every job's `python` and `pip` will point. Fedora marks its system
Python as externally managed and refuses `pip install` into it; the venv is how the gate
job's install of the Gate package succeeds.

### 5b. Register

```sh
gitlab-runner register --non-interactive \
  --url https://<gitlab-host>/ \
  --token glrt-... \
  --executor shell \
  --description laptop-pilot
```

Run as a normal user, this writes `~/.gitlab-runner/config.toml`. If it fails with an
x509 or certificate error, see step 10.

### 5c. Two edits to the configuration

Open `~/.gitlab-runner/config.toml`.

1. At the top, change `concurrent = 1` to `concurrent = 2`, so the plan job and the gate
   job run side by side, as they would on the real fleet.
2. Inside the `[[runners]]` block, add this line:

   ```toml
   pre_build_script = "source $HOME/gate-venv/bin/activate"
   ```

   It runs in the same shell as every job's script, so `python`, `pip` and the
   `fcs-deploy-gate` command the gate job installs all resolve inside the venv.

The block then looks like this, with your own values in the first lines:

```toml
concurrent = 2

[[runners]]
  name = "laptop-pilot"
  url = "https://<gitlab-host>/"
  token = "glrt-..."
  executor = "shell"
  pre_build_script = "source $HOME/gate-venv/bin/activate"
```

### 5d. Start it

In a terminal tab of its own, and leave that tab alone until the demo is over:

```sh
mkdir -p ~/runner && cd ~/runner && gitlab-runner run
```

The runner checks out each job under `~/runner/builds/`. In the pilot project, Settings,
CI/CD, Runners should now list `laptop-pilot` with a green online marker. Nothing runs yet;
there is no pipeline.

## 6. Create the pilot repository and push act one

```sh
git clone https://<gitlab-host>/<group>/lambda-retention-pilot.git ~/lambda-retention-pilot
cp -r ~/fcs-deploy-gate/examples/lambda-retention-pilot/. ~/lambda-retention-pilot/
cd ~/lambda-retention-pilot
sed -i 's#security/fcs-deploy-gate#<group>/fcs-deploy-gate#g' .gitlab-ci.yml
grep -n "fcs-deploy-gate" .gitlab-ci.yml
```

The trailing `/.` on the copy brings the dotfiles, `.gitlab-ci.yml` and `.gitignore`,
along. The `sed` changes the two places that name the Gate project, the `include` and
the `FCS_GATE_PROJECT` variable, and the `grep` should show exactly those two lines with
your group path. The image lines can stay as they are; the shell executor ignores them.

You can drop this `WALKTHROUGH.md` from the pilot repository or keep it; it has no
effect on the pipeline.

```sh
git add -A
git commit -m "Lambda retention pilot, act one"
git push origin main
```

That push is act one.

## 7. Watch the first pipeline

Pilot project, CI/CD, Pipelines, the newest one. The graph shows two stages:

- **test**: `plan` and `fcs-deploy-gate`, running together.
- **deploy**: `apply`, waiting on both.

What a healthy first run looks like:

1. The `plan` job initialises the HTTP backend against GitLab, downloads the AWS and
   archive providers, zips the handler and plans four resources to add.
2. The `fcs-deploy-gate` job clones the Gate, installs it, downloads the pinned CLI,
   verifies its checksum, scans `lambda/`, and prints the summary: two Blocking Findings,
   both on the log group, "CloudWatch Log Group Without KMS" (medium) and "CloudWatch
   Without Retention Period Specified" (informational). The job **passes**, because the
   mode is advisory. Its artifacts, under `fcs-gate/`, hold `summary.md`, `verdict.json`
   and the raw report.
3. The `apply` job creates the role, the policy attachment, the log group and the
   function in the sandbox. The log ends with "Apply complete! Resources: 4 added".

Each act's pipeline takes a few minutes on the laptop, most of it the CLI download and
the provider download. If a job fails, step 10.

Record: the pipeline URL and the three job durations. Download the gate job's artifacts
once; the raw report in there, sanitised, is the fixture ticket #9 is waiting for.

## 8. Confirm in the Falcon console

Two views, the same two you used for the laptop scans.

1. **The scan.** Cloud security, Infrastructure as code, the view that lists scans. The
   pipeline's scan is filed under the project's full path, `<group>/lambda-retention-pilot`,
   not under the bare name the laptop scans used. Open it: the same two Findings on the
   log group.
2. **The IOM.** The posture view for the registered sandbox account. The log group
   `/aws/lambda/fcs-gate-pilot` shows the retention IOM after the next assessment. You
   recorded the assessment cadence; if the apply ran at 18:00 and assessments run every
   few hours, the IOM is there by morning. The policy's name, Severity and resource type
   are what you compare against the Gate's Finding tomorrow.

Record: the time the IOM first appeared, and the policy's exact name and Severity if you
have not already.

## 9. The demo: acts two to four

Every act is a commit on `main` in `~/lambda-retention-pilot`, with the runner tab still
open. Between acts, show the pipeline graph and the gate job's summary.

### Act two: Enforcing

```sh
cd ~/lambda-retention-pilot
sed -i 's/^  FCS_GATE_MODE: advisory/  FCS_GATE_MODE: enforcing/' .gitlab-ci.yml
grep -n FCS_GATE_MODE .gitlab-ci.yml
git commit -am "Act two: the Gate enforces" && git push
```

The gate job prints the same two Findings and now **fails**. The `apply` job is
**skipped**, because it needs the gate job. The sandbox is unchanged. This is the
blocked Deployment.

### Act three: an Exclusion for the Finding the pilot is not about

The KMS Finding is real but outside the retention story, so the Security team approves
an Exclusion for it, with an owner and an expiry. Write `.fcs-gate.yml` at the repository
root, with a real reviewer's name:

```sh
cat > .fcs-gate.yml <<'EOF'
exclusions:
  - rule: iac/d6b2ef53-b734-49cf-b736-f71a2dc70e4f
    file: main.tf
    reason: Log group encryption with a customer-managed key is outside the retention pilot.
    expires: 2026-11-30
    approved_by: <security reviewer>
EOF
git add .fcs-gate.yml
git commit -m "Act three: exclude the KMS Finding, approved and expiring" && git push
```

If act two's summary also listed "IAM Access Analyzer Not Enabled", add a second entry
to the list before committing, with rule `iac/d5900282-4330-48df-b93f-1d76f44f33a2`, the
same `file`, and the reason that the analyzer is enabled per account, not in this module.
That Finding appears on some scans of this module and not on others.

The gate job now reports one Blocking Finding, the retention one, and the Exclusion it
applied. It still **fails**; the apply is still skipped. One rule, one Finding, one line
to fix.

### Act four: the fix

Add one line to the log group in `lambda/main.tf`:

```sh
sed -i 's/^resource "aws_cloudwatch_log_group" "pilot" {/&\n  retention_in_days = 30/' lambda/main.tf
grep -n -A2 'aws_cloudwatch_log_group" "pilot"' lambda/main.tf
git commit -am "Act four: thirty days of retention" && git push
```

The block should now read:

```hcl
resource "aws_cloudwatch_log_group" "pilot" {
  retention_in_days = 30
  name = "/aws/lambda/${local.function_name}"
  ...
```

The gate job reports no Blocking Findings and **passes**. The `apply` job runs and
changes one attribute on the log group. In the console, the IOM closes on the next
assessment. The Gate prevented the IOM in acts two and three; act four shows the same
pipeline letting the fixed change through.

## 10. If something stops

| Symptom | Likely cause | What to do |
|---|---|---|
| `gitlab-runner register` fails with an x509 or certificate error | The runner does not see the corporate CA | Add `tls-ca-file = "/etc/pki/tls/certs/ca-bundle.crt"` inside the `[[runners]]` block; your anchors are already in that bundle |
| Jobs stay "pending" | The runner tab is not running, or "Run untagged jobs" was left unticked | Start `gitlab-runner run`; or edit the runner on the Runners page and tick it |
| A job fails in "Prepare environment" | The job runs a login bash, so your dotfiles run inside it, and one of them assumes a terminal | Put `[[ $- == *i* ]] \|\| return` near the top of `~/.bashrc`; check `~/.bash_logout` for a `clear` |
| Pipeline does not start, "include not found" or "project not found" | The group path in the include is wrong, or the Gate push did not land on `main` | Re-run the `grep` from step 6; check the Gate project's branches |
| Gate job: "You are not allowed to download code from this project" | Job token permissions | Step 3 |
| Gate job: pip reports "externally-managed-environment" | The `pre_build_script` line is missing or outside the `[[runners]]` block | Step 5c, then restart `gitlab-runner run` |
| Gate job: the CLI download or the token request fails, but the same works in your own shell | The job's login shell does not load the proxy variables your interactive shell has | Add `HTTPS_PROXY` and `NO_PROXY` as project variables; both the Gate and the CLI honour them |
| Gate job: "could not scan", exit code outside 0 and 10 to 40 | A real CLI error; the summary quotes its last lines | Read the quoted lines; the Gate README's "How the Gate decides" lists the cases |
| `plan` fails on `terraform init` with 403 | Infrastructure feature off | Step 4a |
| `plan` fails downloading providers | No reach to the Terraform registry | Point `TF_CLI_CONFIG_FILE` at a mirror configuration, or open the egress |
| `apply` fails on IAM | The sandbox credentials cannot create or pass a role | Widen the sandbox role; only four resources are involved |
| The console shows no pipeline scan after ten minutes | Looking under the wrong name | Search the full path `<group>/lambda-retention-pilot`, not the bare name |

The gate job reuses `/tmp/fcs-gate` between runs on the same machine. The Gate recreates
that directory and overwrites its outputs each run, so the reuse is harmless.

## 11. After the demo

**Stop the runner.** Interrupt the runner tab, then:

```sh
gitlab-runner unregister --name laptop-pilot
```

and delete `laptop-pilot` on the pilot project's Runners page.

**Destroy the sandbox resources.** The state is in GitLab, so Terraform needs the same
backend arguments the pipeline used, with a personal access token in place of the job
token. Create a token with the `api` scope and a short expiry, export the sandbox
credentials in your shell, then:

```sh
cd ~/lambda-retention-pilot/lambda
STATE="https://<gitlab-host>/api/v4/projects/<project id>/terraform/state/pilot"
terraform init -input=false -reconfigure \
  -backend-config="address=$STATE" \
  -backend-config="lock_address=$STATE/lock" \
  -backend-config="unlock_address=$STATE/lock" \
  -backend-config="username=<your gitlab username>" \
  -backend-config="password=<personal access token>" \
  -backend-config="lock_method=POST" \
  -backend-config="unlock_method=DELETE"
terraform destroy -var region=us-gov-west-1
```

The project id is on the pilot project's overview page, under its name. Revoke the token
afterwards. Do not put it in a file.

**Bring back** for the repository, none of it naming the host or the account:

- The gate job's raw report from the artifacts, sanitised, as the parser fixture (#9).
- The menu paths you used for the IaC scan view and the posture view.
- The IOM policy's exact name, Severity and resource type, and the assessment cadence (#10).
- Anything in this walkthrough that did not match what you saw.
