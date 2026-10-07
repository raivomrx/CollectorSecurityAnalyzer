# CSA delivery workflow

The user has authorized GitHub delivery as the default completion step for CSA
development work. After implementing and validating an agreed change, commit
and push it to the repository's existing working branch unless the user asks
for another branch or a pull request. Check the GitHub Actions runs for that
exact commit and resolve failures caused by the change.

For changes shipped in CSA Lab, wait for the GitHub installer build and artifact
upload to finish, then include the GitHub installer artifact or build link in
the final response. State any validation or signing limits accurately. Never
commit credentials, customer evidence, session enrollment tokens or local build
outputs; use the existing GitHub Actions artifact workflow for the installer.

This preference was explicitly requested by the user on 2026-10-07.
