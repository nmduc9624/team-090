# Hunt Package Output Schema

The AI should return structured output with these sections:

```json
{
  "threat_summary": "",
  "key_behaviors": [],
  "ioc": {
    "domains": [],
    "ips": [],
    "hashes": [],
    "files": [],
    "processes": [],
    "registry_keys": []
  },
  "mitre_mapping": [],
  "required_telemetry": [],
  "hunt_checklist": [],
  "query_drafts": [
    {
      "name": "",
      "platform": "KQL | SPL | generic",
      "query": "",
      "purpose": ""
    }
  ],
  "correlation_logic": "",
  "escalation_condition": "",
  "analyst_notes": ""
}
```

Generated queries are drafts. Analysts must review and adapt them to the real SIEM/EDR schema.
