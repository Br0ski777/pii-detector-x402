import type { ApiConfig } from "./shared";

export const API_CONFIG: ApiConfig = {
  name: "pii-detector",
  slug: "pii-detector",
  description: "Detect PII in text: emails, phones, SSNs, credit cards, IPs, addresses. Regex-based.",
  version: "1.0.0",
  routes: [
    {
      method: "POST",
      path: "/api/detect",
      price: "$0.005",
      description: "Detect personally identifiable information (PII) in text",
      toolName: "compliance_detect_pii",
      toolDescription:
        "Use this when you need to scan text for personally identifiable information (PII). Detects emails, phone numbers (international), credit card numbers (with Luhn validation), US SSNs, dates of birth, IP addresses, postal addresses (US/UK/FR), passport numbers, and URLs with tokens. Returns each match with type, redacted value, position, and confidence. Includes overall risk level (low/medium/high/critical). Do NOT use for email validation — use email_verify_address. Do NOT use for GDPR compliance — use compliance_scan_gdpr.",
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
    },
  ],
};
