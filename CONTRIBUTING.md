# Contributing to SecureTrack Crypto Library

Thank you for your interest in contributing to the SecureTrack Crypto Library! This document provides guidelines and instructions for contributing to this security-focused project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone. Please be considerate in your communication and actions.

## Security First

This is a security-focused library. All contributions must maintain or improve the security posture of the library:

- No compromises on security for convenience
- All cryptographic implementations must follow industry best practices
- Security considerations must be clearly documented

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/SecureTrack-Encryption.git`
3. Create a new branch for your contribution: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Test your changes thoroughly
6. Submit a pull request

## Development Setup

Follow these steps to set up your development environment:

```bash
# Install Rust and required tools
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli

# Build the project
cargo build

# Run tests
cargo test
cargo test --target wasm32-unknown-unknown

# Build for WASM
cargo build --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir ./pkg ./target/wasm32-unknown-unknown/release/securetrack_crypto.wasm
```

## Contribution Guidelines

### Documentation

- All public functions must have comprehensive documentation
- Security considerations must be explicitly stated
- Examples should be provided for complex functionality

### Code Style

- Follow standard Rust style conventions
- Use `cargo fmt` to format your code
- Use `cargo clippy` to check for potential issues

### Testing

- All contributions must include appropriate tests
- Coverage for new functionality should be comprehensive
- Include tests for edge cases and error conditions

### Pull Request Process

1. Ensure all tests pass
2. Update documentation if necessary
3. Describe the changes and their purpose in the PR description
4. Link any relevant issues
5. Be responsive to feedback and code review comments

## Security Vulnerability Reporting

If you discover a security vulnerability, please do **NOT** create a public issue. Instead, please email security@securetrack.app with details of the vulnerability.

We'll work with you to address the vulnerability and provide appropriate credit if desired.

## License

By contributing to this project, you agree that your contributions will be licensed under the project's MIT License.

## Questions?

If you have any questions or need help with your contribution, feel free to open an issue asking for guidance or clarification.
