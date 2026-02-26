# AGENTS.md - Developer Guidelines for Quorumeum

This file provides guidelines for AI agents operating in the Quorumeum codebase.
Quorumeum is a Bitcoin Core fork implementing federated signet block signing (10-of-100 threshold).

## Build Commands

### Full Build
```bash
cd /Users/johnny/repos/bitcoin/bitcoin
cmake -B build
cmake --build build -j$(nproc)
```

### Build Specific Target
```bash
cmake --build build --target bitcoin_node -j4
cmake --build build --target test_bitcoin -j4
```

### Clean Build
```bash
rm -rf build && cmake -B build
```

### Configure for Debug
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
```

## Lint Commands

### Run All Lints (via Docker)
```bash
DOCKER_BUILDKIT=1 docker build -t bitcoin-linter --file "./ci/lint_imagefile" ./ && docker run --rm -v $(pwd):/bitcoin -it bitcoin-linter
```

### Run Individual Lint Scripts
```bash
test/lint/lint-python.py
test/lint/lint-shell.py
test/lint/lint-spelling.py
```

### Run Python linter (flake8/ruff)
```bash
ruff check test/functional/
flake8 test/functional/
```

### Run clang-format
```bash
clang-format -i src/*.cpp src/*.h
```

## Test Commands

### Run Single Functional Test
```bash
build/test/functional/test_runner.py test/functional/p2p_signetpsbt.py
# Or directly:
build/test/functional/p2p_signetpsbt.py
```

### Run Single Unit Test
```bash
build/src/test/test_bitcoin --run_test=signetpsbt_tests
```

### Run All Tests
```bash
# Functional tests
build/test/functional/test_runner.py

# Unit tests
build/src/test/test_bitcoin

# Both
ctest --test-dir build
```

### Test Options
```bash
# Run with timeout disabled (for debugging)
build/test/functional/p2p_signetpsbt.py --timeout-factor 0

# Run with verbose output
build/test/functional/p2p_signetpsbt.py -l DEBUG

# Run specific test within a file
build/src/test/test_bitcoin --run_test=signetpsbt_tests/signetpsbt_serialization
```

## Code Style Guidelines

### C++ Formatting
- **Indentation**: 4 spaces (no tabs)
- **Braces**: New line for classes/functions/methods; same line for control structures
- **Line length**: Prefer <100 characters
- **Use clang-format**: Run `clang-format -i` on changed files before committing

### C++ Naming Conventions
- **Variables/functions**: snake_case (e.g., `node_id`, `get_peer_info`)
- **Classes/structs**: UpperCamelCase (e.g., `CNode`, `PeerManager`)
- **Member variables**: `m_` prefix (e.g., `m_count`)
- **Global variables**: `g_` prefix (e.g., `g_connman`)
- **Constants**: ALL_CAPS with underscores (e.g., `MAX_MESSAGE_SIZE`)
- **Enums**: snake_case, PascalCase, or ALL_CAPS

### C++ Error Handling
- **`Assert()` / `static_assert`**: Document assumptions for fatal bugs
- **`CHECK_NONFATAL`**: Recoverable internal errors (throws exception)
- **`Assume`**: Non-fatal assumptions (silent in production)
- **Never use `assert`** in new code; use `Assert()` from `<util/check.h>`
- **Use `nullptr`** instead of `NULL` or `(void*)0`

### C++ Imports
- Use angle brackets for system headers: `#include <vector>`
- Use quotes for local headers: `#include "net_processing.h"`
- Group includes: system, bitcoin internal, local (blank line between groups)
- Sort alphabetically within groups

### C++ Misc
- Prefer `++i` over `i++`
- Use list initialization: `int x{0};` not `int x = 0;`
- Use functional casts: `int(x)` not `(int)x`
- Use `std::optional` for optional return values

### Python Style (Functional Tests)
- Follow [PEP-8](https://www.python.org/dev/peps/pep-0008/)
- Use type hints
- Avoid wildcard imports
- Sort imports lexicographically
- Use f-strings: `f'{x}'` not `'{}'.format(x)`
- Use `__slots__` for P2P message classes to reduce memory

### Test Naming
- `<area>_test.py` (e.g., `p2p_signetpsbt.py`, `feature_quorumeum.py`)
- Areas: `feature`, `interface`, `mempool`, `mining`, `p2p`, `rpc`, `tool`, `wallet`
- Don't include redundant `test` in name

### Comments
- **C++**: Use Doxygen-style `/** */` for functions/classes
- **Python**: Use docstrings for modules/classes/functions
- Comment the "why", not the "what"

## Project-Specific Notes

### Quorumeum Overview
Quorumeum is a Bitcoin Core fork (v30.2) running on a custom signet where each block must be signed by 10 out of 100 signing members using Taproot multisig.

### New Configuration Options
- `-federation_privatekey` - Private key for signing blocks (signet participant)
- `-federation_multisig` - Multisig descriptor for the federation (10-of-100)
- `-descriptor` - Descriptor wallet for key management

### New P2P Message: signetpsbt
The `signetpsbt` message (cmdString: "signetpsbt", v2 transport ID: 30) relays PSBTs and block templates for federated signing:
- Message format: nonce (uint64), psbt (compactsize + data), block_template (compactsize + data), signers_short_ids (array of 8-byte IDs)
- Short IDs derived via SipHash-2-4: `short_id = SipHash(key=nonce, data=pubkey)`
- Handler: `ProcessSignetPsbt()` in `src/net_processing.cpp`

### Key Files for signetpsbt Implementation
- `src/signetpsbt.h` - SignetPsbtMessage struct with serialization, SigningSessionManager
- `src/signetpsbt.cpp` - ProcessSignetPsbt() handler and relay logic
- `src/net_processing.cpp` - ProcessSignetPsbt() call site (lines ~4926)
- `src/node/context.h` - NodeContext fields: federation_key, federation_descriptor, signing_session
- `src/protocol.h` - NetMsgType::SIGNETPSBT registration (line 66)
- `src/net.cpp` - V2_MESSAGE_IDS array (index 30)
- `src/script/descriptor.h` - Descriptor class for federation keys
- `test/functional/p2p_signetpsbt.py` - Functional test
- `src/test/signetpsbt_tests.cpp` - Unit tests

### NodeContext Fields (in src/node/context.h)
- `federation_key` - Extended private key for signing blocks (CExtKey)
- `federation_descriptor` - Descriptor for the federation (10-of-100 Taproot multisig)
- `signing_session` - SigningSessionManager for active signet PSBT signing sessions

### Legacy Global Variables
- `g_descriptor` - Legacy global for federation descriptor (use NodeContext instead)
- `g_connman` - Network connection manager

### Docker/TOR Setup
```bash
./control.sh build   # Build docker image
./control.sh up      # Start node with TOR hidden service
./control.sh down    # Stop the node
```

### Surrender Policy
When a new block is found during a signing session, all current signing sessions are dropped. Check block height in block template to detect new blocks.

### AGENTS.md Maintenance Policy
When implementing significant federation-related changes, always update this file:
- **New configuration options**: Add to "New Configuration Options" section
- **New NodeContext fields**: Update "NodeContext Fields" section  
- **New P2P messages**: Update "New P2P Message" section with format details
- **Key files**: Update "Key Files for signetpsbt Implementation" section
- **Global variables**: Update "Legacy Global Variables" section
- **Protocol changes**: Update "Signet PSBT Protocol" section or create new QIP section

Use `[federation]` prefix for all federation-related logs in C++ code.

### TODO Format
Use clear TODO comments for incomplete features:
```cpp
// TODO: Implement full signature validation with pubkey recovery
// TODO: Add relay logic to flood-fill to peers
// TODO: Sign PSBT and append short ID
// TODO: Block publication when threshold (10) reached
```

### Signet PSBT Protocol (QIP-001)
Refer to `QIPs/QIP-001.md` for the full protocol specification including:
- Message format and encoding
- Relay rules and processing order
- DoS protection (ban invalid signers)
- Block publication when threshold reached

## References
- [Developer Notes](doc/developer-notes.md) - Full coding guidelines
- [Test README](test/README.md) - Functional test documentation
- [QIP-001](QIPs/QIP-001.md) - signetpsbt protocol specification
- [contrib/signet/README.md](contrib/signet/README.md) - PSBT-based signet mining
- [feature_quorumeum.py](test/functional/feature_quorumeum.py) - Proof of concept test