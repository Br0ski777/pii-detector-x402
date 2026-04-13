import type { ApiConfig } from "./shared";

export const API_CONFIG: ApiConfig = {
  name: "pii-detector",
  slug: "pii-detector",
  description: "Detect PII in text -- emails, phones, SSNs, credit cards, IPs, addresses. Risk scoring, redaction support.",
  version: "1.0.0",
  routes: [
    {
      method: "POST",
      path: "/api/detect",
      price: "$0.005",
      description: "Detect personally identifiable information (PII) in text",
      toolName: "compliance_detect_pii",
      toolDescription:
        `Use this when you need to scan text for personally identifiable information (PII). Returns detected PII entities with redaction in JSON.

Returns: 1. matches array with type, value (redacted), position, confidence 2. riskLevel (low/medium/high/critical) 3. totalMatches count 4. PII types detected: email, phone, creditCard (Luhn validated), ssn, dateOfBirth, ipAddress, postalAddress, passportNumber, urlWithToken.

Example output: {"text":"Contact john@example.com or 555-123-4567","matches":[{"type":"email","value":"j***@example.com","position":[8,24],"confidence":0.99},{"type":"phone","value":"555-***-4567","position":[28,40],"confidence":0.95}],"riskLevel":"high","totalMatches":2}

Use this BEFORE publishing content, FOR compliance auditing, data leak prevention, log sanitization, and GDPR data subject access requests.

Do NOT use for email validation -- use email_verify_address instead. Do NOT use for website GDPR compliance -- use compliance_scan_gdpr instead. Do NOT use for phone validation -- use phone_validate_number instead.`,
      inputSchema: {
        type: "object",
        properties: {
          text: {
            type: "string",
            description: "Text content to scan for PII",
          },
        },
        required: ["text"],
      },
      outputSchema: {
          "type": "object",
          "properties": {
            "found": {
              "type": "boolean",
              "description": "Whether PII was detected"
            },
            "count": {
              "type": "number",
              "description": "Number of PII items found"
            },
            "categories": {
              "type": "object",
              "description": "PII by category (email, phone, SSN, etc.)"
            },
            "redacted": {
              "type": "string",
              "description": "Text with PII redacted"
            },
            "items": {
              "type": "array",
              "items": {
                "type": "object",
                "properties": {
                  "type": {
                    "type": "string"
                  },
                  "value": {
                    "type": "string"
                  },
                  "start": {
                    "type": "number"
                  },
                  "end": {
                    "type": "number"
                  }
                }
              }
            }
          },
          "required": [
            "found",
            "count"
          ]
        },
    },
  ],
};
