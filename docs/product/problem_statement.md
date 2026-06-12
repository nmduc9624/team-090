# Problem Statement

SOC Junior analysts often receive long threat reports, CVE advisories, and malware write-ups. The hard part is not just reading them, but translating them into concrete hunting work: what telemetry is needed, which indicators matter, which behaviors should be searched, and what query logic should be used.

This project builds an AI assistant that turns unstructured threat intelligence into a structured hunt package. The output should help a junior analyst run an investigation faster while still requiring human review before any real action.

## Target User

SOC Junior Analyst / SOC L1 Analyst who needs to prepare initial threat hunting checks from external or internal threat intelligence.

## AI Value

AI is useful because threat reports are written in natural language, vary in format, and often describe behaviors rather than simple IOC lists. The assistant reads the report, extracts technical meaning, maps it to telemetry, and drafts queries/checklists that would otherwise require a senior threat hunter or detection engineer.
