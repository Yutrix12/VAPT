"""Fixes that code gives without the LLM (deterministic fix first, U2).

Vulnerabilities: Trivy's fixed versions (in trivy_parser). Misconfigurations:
Trivy's own Resolution text (in trivy_parser; None when the report has
none). Licenses: name, category and link (in trivy_parser). Secrets: the
fixed steps below. Step U4 adds the code-built upgrade commands here.
"""

# Order and wording follow GitHub's "Removing sensitive data from a
# repository" (docs.github.com/en/authentication/keeping-your-account-and-
# data-secure/removing-sensitive-data-from-a-repository, read 2026-11-11):
# revoke or rotate first; git-filter-repo is the tool it names; a rewrite
# does not reach other clones, forks or pull requests.
SECRET_FIX_STEPS = (
    "Revoke or rotate the credential at its provider first: once it is revoked, it can no longer be "
    "used, whatever happens to the file.",
    "Remove it from the code, and load the new value from a secret store or an environment variable "
    "instead.",
    "If the old value must also leave the git history, rewrite the history with git-filter-repo and "
    "force-push. Copies in other people's clones, forks and pull requests stay, which is why revoking "
    "comes first.",
)
