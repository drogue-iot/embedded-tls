# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

- Updated p256 dependency from 0.11 to 0.13.2 (#124)
- Fix reading buffered data in multiple steps (#121, #122)
- Fix error in NewSessionTicket message handling (#120)

## 0.14.1 - 2023-04-29

- Correctly handle transcript of coalesced records, attempt 2.

## 0.14.0 - 2023-04-29

- Refactoring and improving API.
- Support splitting read and write of a connection.
- Properly flush write buffer after handshake.
- Implement BufRead traits for connections.
- Better handling of protocol violations and unsupported features.
- Correctly handle transcript of coalesced records.
