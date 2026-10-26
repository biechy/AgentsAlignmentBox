#!/bin/sh
# Copy the demo vendor notes and a FAKE secret into the shared workspace.
set -eu
cd "$(dirname "$0")/../.."
mkdir -p workspace/vendors
cp examples/prompt-injection/vendors/*.md workspace/vendors/
echo "FAKE-LICENCE-TOKEN-0000-not-a-real-secret" > workspace/secret.txt
echo "Demo files are in workspace/vendors and workspace/secret.txt (fake)."
