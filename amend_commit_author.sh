#!/bin/bash

# amend_commit_author.sh
#
# This script rewrites the author and committer information for a range of commits
# from a specified starting commit up to the current HEAD.
#
# WARNING: This script rewrites Git history. It should ONLY be used on branches
# that have not been shared with others or on feature branches where you are
# certain that a force-push is acceptable and expected.
# Rewriting history of shared branches (like main/master or develop) can cause
# significant problems for collaborators.

set -e # Exit immediately if a command exits with a non-zero status.

# --- Configuration ---
NEW_AUTHOR_NAME="Tyler Zervas"
NEW_AUTHOR_EMAIL="tz-dev@vectorwieght.com" # Corrected typo from vectorwieght to vectorweight
# --- End Configuration ---

# --- Helper Functions ---
print_usage() {
  echo "Usage: $0 <STARTING_COMMIT_REF>"
  echo ""
  echo "Arguments:"
  echo "  <STARTING_COMMIT_REF>  The commit hash, branch name, or tag from which to start"
  echo "                         rewriting history. The script will rewrite this commit"
  echo "                         and all subsequent commits up to the current HEAD."
  echo "                         Use 'HEAD~N' to specify the last N commits."
  echo "                         Use <FIRST_COMMIT_HASH>^ to rewrite from the very first commit."
  echo ""
  echo "Example: Amend the last 3 commits"
  echo "  $0 HEAD~3"
  echo ""
  echo "Example: Amend all commits on the current branch since it diverged from 'main'"
  echo "  $0 \$(git merge-base main HEAD)"
  echo ""
  echo "Example: Amend all commits from a specific commit hash"
  echo "  $0 abc123xyz"
  echo ""
  echo "Important Notes:"
  echo " - This script uses 'git rebase -i --exec'. It will open an editor for the"
  echo "   interactive rebase. You typically just need to save and close the editor"
  echo "   if all commits are to be 'pick'ed and processed."
  echo " - After running this script, you will likely need to force-push the branch"
  echo "   to any remote repository (e.g., 'git push --force-with-lease origin your-branch')."
  echo " - Ensure you are on the correct branch before running this script."
  echo " - The original committer date is preserved."
}

# --- Main Script ---

# Check if a starting commit reference is provided
if [ -z "$1" ]; then
  echo "Error: No starting commit reference provided."
  print_usage
  exit 1
fi

STARTING_COMMIT_REF="$1"

# Verify that the starting commit reference is valid
if ! git rev-parse --verify "${STARTING_COMMIT_REF}^{commit}" > /dev/null 2>&1; then
  echo "Error: Invalid starting commit reference: '$STARTING_COMMIT_REF'"
  echo "Please provide a valid commit hash, branch name, tag, or reference like HEAD~N."
  exit 1
fi

# Confirm the user wants to proceed
echo "You are about to rewrite history from commit '$STARTING_COMMIT_REF' to HEAD."
echo "The new author will be: $NEW_AUTHOR_NAME <$NEW_AUTHOR_EMAIL>"
echo "The original commit dates will be preserved."
echo ""
echo "THIS IS A DESTRUCTIVE OPERATION. MAKE SURE YOU UNDERSTAND THE CONSEQUENCES."
read -p "Are you sure you want to continue? (yes/no): " confirmation

if [ "$confirmation" != "yes" ]; then
  echo "Operation cancelled by the user."
  exit 0
fi

echo "Starting history rewrite..."

# The GIT_SEQUENCE_EDITOR is set to 'true' to automatically accept the rebase plan.
# The --exec part will run for each commit in the rebase.
# We preserve the original commit date using GIT_COMMITTER_DATE.
GIT_SEQUENCE_EDITOR=true git rebase -i --rebase-merges --exec \
  "GIT_COMMITTER_NAME='${NEW_AUTHOR_NAME}' GIT_COMMITTER_EMAIL='${NEW_AUTHOR_EMAIL}' \
   GIT_AUTHOR_NAME='${NEW_AUTHOR_NAME}' GIT_AUTHOR_EMAIL='${NEW_AUTHOR_EMAIL}' \
   git commit --amend --no-edit --reset-author --date=\$(git show -s --format=%ad)" \
  "${STARTING_COMMIT_REF}^"
  # The ^ on STARTING_COMMIT_REF ensures that the specified commit itself is included in the rebase.

echo ""
echo "History rewrite complete."
echo "Please review the changes with 'git log'."
echo "If the changes are correct, you may need to force-push your branch:"
echo "  git push --force-with-lease <remote_name> <branch_name>"
echo ""
echo "Author name set to: $NEW_AUTHOR_NAME"
echo "Author email set to: $NEW_AUTHOR_EMAIL"

exit 0
