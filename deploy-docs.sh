#!/bin/bash
set -o errexit -o nounset

rev=$(git rev-parse --short HEAD)

cd target/doc

git init
git config user.name "Zachary Bush"
git config user.email "zach@zmbush.com"

git remote add upstream "https://$GH_TOKEN@github.com/zmbush/crypto_vault.git"
git fetch upstream
git reset upstream/gh-pages

touch .
git add -A .
git commit -m "Rebuild pages at ${rev}"
git push -q upstream HEAD:gh-pages
