#!/bin/bash

# Firewall Test Runner
echo "Running Firewall Test Suite..."

# Build tests
make clean
make test

# Run unit tests
echo "=== Unit Tests ==="
./bin/firewall_test

# Run integration test
echo "=== Integration Test ==="
./bin/integration_test

# Memory leak check with valgrind
if command -v valgrind &> /dev/null; then
    echo "=== Memory Check ==="
    valgrind --leak-check=full --track-origins=yes ./bin/firewall_test
fi

echo "=== Test Complete ==="
