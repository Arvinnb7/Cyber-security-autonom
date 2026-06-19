# Attack Models — plug-in point

This folder is where **your attack-model definitions** live. The platform loads
every `*.json` file here at runtime via
`backend/app/simulation/scenarios.py::load_external_scenarios()` and can use them
to extend the built-in attack scenarios and detection rules.

## Why this exists

The built-in scenarios (`account_takeover`, `ransomware`, `data_exfiltration`,
`anomalous_privileged`) are realistic but generic. Drop your own learned attack
patterns here to make detection match *your* environment without changing code.

## Format

Each file is a JSON object describing one scenario as an ordered chain of events
that should correlate into a single incident:

```jsonc
{
  "name": "okta_session_hijack",
  "threat_type": "account_takeover",   // maps to the scoring baseline
  "description": "Stolen session token replayed from a new ASN",
  "events": [
    { "source": "okta", "category": "authentication", "action": "login_success",
      "country": "US", "severity": 2 },
    { "source": "okta", "category": "authentication", "action": "session_replay",
      "country": "RU", "severity": 4, "raw": { "asn": "AS12345" } }
  ]
}
```

See `sample_attack_model.json.example` for a complete example. Rename it to
`*.json` to activate it.

## Roadmap

`load_external_scenarios()` returns the parsed definitions today; wiring them into
the scenario registry and the detector rule set is the next integration step
(Milestone 3/4 in the project plan).
