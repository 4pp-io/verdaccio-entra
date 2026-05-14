# Contributing

We welcome questions, bug reports, and pull requests.

## Before opening an issue

- Search existing issues first
- Check the [README](README.md) and Verdaccio's [plugin docs](https://verdaccio.org/docs/plugin-auth)

## Pull requests

- Run `npm test` and `npm run lint` before submitting
- Add a [changeset](https://github.com/changesets/changesets) (`npx changeset`) for user-facing changes
- Keep PRs focused — one concern per PR

## Local Workflow Testing

You can test GitHub Actions workflows locally using [act](https://github.com/nektos/act).

```bash
# Run pull_request workflows (standard PR check)
npm run test:workflows

# Run push workflows (simulates a push to the PR branch)
npm run test:workflows:push

# Run issue_comment workflows (simulates /publish-pr command)
npm run test:workflows:comment

# Run all workflow types sequentially
npm run test:workflows:all
```

### Safe Secret Handling

Workflows that interact with the GitHub API (e.g., `gh pr checks`) require a `GITHUB_TOKEN`.

By default, `act` uses an internal dummy token with no permissions. To run workflows that require API access:

1.  **Use a Read-Only Token:** Create a [Fine-Grained Personal Access Token](https://github.com/settings/tokens?type=beta) with strictly **Read-only** permissions (`Metadata: Read-only`, `Pull requests: Read-only`) for this repository.
2.  **Configure `.secrets`:** Create a file named `.secrets` in the project root (this file is ignored by git):
    ```env
    GITHUB_TOKEN=github_pat_...
    ```
3.  **Run Tests:** `act` will automatically load this token when you run `npm run test:workflows`.

**Security Note:** Never use a token with write access for local testing in Docker containers. Using a read-only PAT ensures that your local environment cannot accidentally (or maliciously) modify your repository.

**Note on Git State:**
- **Dirty Changes:** Your local modifications (even if uncommitted) are visible to the runner.
- **Untracked Files:** Included unless they match a pattern in `.gitignore`.
- **Stashes:** Not applied. If you need to test stashed code, apply it before running `act`.
- **Clean Run:** For the most accurate simulation of a GitHub runner, ensure your working tree is clean (`git status` is empty).

## Code of conduct

Be respectful. No abusive, harassing, or discriminatory behavior.
