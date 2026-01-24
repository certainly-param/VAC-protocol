# Contributing to VAC Protocol

Thank you for your interest in contributing to the VAC (Verifiable Agentic Credential) Protocol!

## Getting Started

1. **Fork the repository** and clone it locally
2. **Install Rust 1.70+**: [rustup.rs](https://rustup.rs/)
3. **Build the project**:
   ```bash
   cd sidecar
   cargo build
   ```
4. **Run tests**:
   ```bash
   cargo test --lib -- --test-threads=1  # Config tests need single thread
   cargo test --test integration_test
   ```

## Project Structure

```
vac/
├── sidecar/        # Core VAC sidecar implementation
├── control-plane/  # Mock control plane for testing
├── demo-api/       # Demo upstream API
├── docs/           # Documentation
└── adapters/       # WASM adapter examples
```

## How to Contribute

### Reporting Bugs

- Check existing issues first
- Include Rust version (`rustc --version`)
- Provide minimal reproduction steps
- Include relevant logs (with sensitive data redacted)

### Suggesting Features

- Open an issue with `[Feature]` prefix
- Describe the use case and expected behavior
- Reference relevant sections of the [Architecture](docs/ARCHITECTURE.md) or [Security](docs/SECURITY.md) docs

### Pull Requests

1. **Create a branch** from `main`
2. **Write tests** for new functionality
3. **Follow Rust conventions**: `cargo fmt` and `cargo clippy`
4. **Update documentation** if needed
5. **Keep commits atomic** with clear messages

### Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy` and address warnings
- Add doc comments for public APIs
- Follow existing patterns in the codebase

## Development Guidelines

### Security Considerations

VAC is a security-critical project. When contributing:

- **Never log secrets** (API keys, tokens, etc.)
- **Fail closed** - deny by default on errors
- **Validate all inputs** - especially from untrusted sources (agents)
- **Review the [Security Guide](docs/SECURITY.md)** before making security-related changes

### Testing

- Unit tests go in the same file as the code (`#[cfg(test)]`)
- Integration tests go in `sidecar/tests/`
- Config tests require `--test-threads=1` due to env var isolation

### Documentation

- Update relevant docs in `docs/` for user-facing changes
- Add inline doc comments for public functions
- Keep README.md Quick Start up to date

## Questions?

- Read the [Architecture Guide](docs/ARCHITECTURE.md) for system overview
- Check the [API Reference](docs/API.md) for protocol details
- Open an issue for questions not covered in docs

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
