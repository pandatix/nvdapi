# Contributing to the Go NVD API project

Welcome to the Go NVD API contributing guide. We are excited about the prospect of you joining our community !

## Getting started

Contributing to the project follows the standard pipeline:
 - fork the repo
 - create and checkout a branch
 - create, modify and/or delete a part of the project
 - create a pull request (you may squash your commits into one) going from your branch to `nvdapi/dev`
 - stay near to answer our questions and help during the code review

When `dev` content has been tested enough, it will be merged into `master` and will be into the next release.

## Commits name convention

To help reviewing commit history, your commits must follow the following pattern: `[Fixes #<issue-number>] <what changed>`.

With this complex convention, you are able to use a little emoji of your choice to make your commit a bit funnier. 🐢 🐥

## Pull requests

When your code is ready to get submitted, [open a pull request](https://github.com/PandatiX/nvdapi/pulls) with an explicit and synthetic name, and describe what has changed through your submission using the description text box.
A clear description will help us during the review process.

In case you don't think it's ready to get reviewed, you may add `WIP: ` at the beginning of the pull request name.

In case we don't think it's ready to get embeded in the project, you may provide additional commits and explanations.

Don't forget that we mainly rebase instead of merging to avoid conflicts. In case you think it won't be useful to do so, say so in your pull request so that it'll speed up the process.
