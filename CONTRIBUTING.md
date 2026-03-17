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
# Run workflows triggered by pull_request (default behavior)
npm run test:workflows

# Run all workflows (including push, etc.)
npm run test:workflows:all
```

**Note on Git State:**
- **Dirty Changes:** Your local modifications (even if uncommitted) are visible to the runner.
- **Untracked Files:** Included unless they match a pattern in `.gitignore`.
- **Stashes:** Not applied. If you need to test stashed code, apply it before running `act`.
- **Clean Run:** For the most accurate simulation of a GitHub runner, ensure your working tree is clean (`git status` is empty).

## Code of conduct

Be respectful. No abusive, harassing, or discriminatory behavior.
