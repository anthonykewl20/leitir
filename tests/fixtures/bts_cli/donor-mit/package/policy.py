# SPDX-License-Identifier: MIT
# Contract-shaped synthetic donor for the port_contract CLI tests. Unlike
# tests/fixtures/bts_cli/donor, this fixture carries a real, resolvable
# SPDX license header so a positive port-attribution test has real license
# evidence to resolve -- see tests/test_port_contract_cli.py.
def normalize_contract(value):
    return value
