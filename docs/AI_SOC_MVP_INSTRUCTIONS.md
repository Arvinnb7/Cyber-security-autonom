# AI SOC MVP Detection Catalog

Use `ai_soc_mvp_detection_catalog.json` as the source of truth for the MVP detection engine.

## Build requirements

- Create a Detection Catalog database/schema based on the JSON fields.
- Create APIs to list, read, create, update, and delete detection definitions.
- Create a scoring engine that calculates:
  - threat_score
  - user_risk_score
  - asset_risk_score
  - business_impact_score
  - final_risk_score
- Create an AI investigation module that explains:
  - what happened
  - why it matters
  - what evidence supports the detection
  - what action is recommended
  - whether human approval is required
- Create a dashboard that shows:
  - active high-risk detections
  - detections by severity
  - top risky users
  - top risky assets
  - incident timeline
- Use the 10 detections in the JSON as the MVP scope.
- Do not add unrelated features before these detections are implemented and testable.
