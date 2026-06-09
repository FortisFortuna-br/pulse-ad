"""Ingest adapters: turn collected recon data into a Pulse graph.

Pulse does not collect data itself. It consumes the output of established,
authorized collectors so the operator stays on the right side of the line:

    on-prem  -> SharpHound  (BloodHound JSON)
    cloud    -> AzureHound / ROADrecon

Each adapter is intentionally lenient: missing fields are skipped, never fatal.
"""
