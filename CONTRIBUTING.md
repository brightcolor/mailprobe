# Contributing

Thanks for contributing to MailProbe.

## Development Setup

1. Fork and clone the repository.
2. Copy `.env.example` to `.env`.
3. Start local services with:
   ```bash
   docker compose up -d
   ```
4. Run tests before opening a PR:
   ```bash
   go test ./...
   ```

## Pull Request Guidelines

- Keep changes focused and small.
- Add or update tests for behavior changes.
- Keep runtime footprint low (this project targets small VPS setups).
- Update `README.md` and `.env.example` if config or operations change.
- Write clear commit messages.

## Security

- Do not commit secrets.
- Use `.env` for local secrets.
- For security issues, open a private report instead of a public issue.

