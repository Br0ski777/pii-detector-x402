# PII Detector API

[![MCP Server](https://img.shields.io/badge/MCP-server-blue)](https://pii-detector.api.klymax402.com/mcp)
[![x402](https://img.shields.io/badge/payments-x402-6E56CF)](https://x402.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Detect PII in text: emails, phones, SSNs, credit cards, IPs, addresses. Regex-based. Pay-per-call via [x402](https://x402.org) (USDC on Base L2) -- no API key, no signup, no rate-limit wall.

Part of the [klymax402](https://klymax402.com) marketplace -- 100 x402 micropayment APIs for AI agents, one wallet, USDC on Base.

## Quickstart -- MCP

Add to your MCP client config (Claude Desktop, Cursor, ElizaOS, etc.):

```json
{
  "mcpServers": {
    "pii-detector": {
      "url": "https://pii-detector.api.klymax402.com/mcp"
    }
  }
}
```

## Quickstart -- HTTP (x402)

```bash
curl -X POST "https://pii-detector.api.klymax402.com/api/detect" \
  -H "Content-Type: application/json" \
  -d '{"text":"..."}'
# -> 402 Payment Required, with an x402 payment challenge in the response body
```

Any x402-aware client ([`@x402/fetch`](https://www.npmjs.com/package/@x402/fetch), [`x402-agent-tools`](https://www.npmjs.com/package/x402-agent-tools), ATXP) handles the 402 -> sign -> retry cycle automatically.

## Tools

| Tool | Method | Path | Price | Description |
|---|---|---|---|---|
| `compliance_detect_pii` | POST | `/api/detect` | $0.012 | Detect personally identifiable information (PII) in text |

### `compliance_detect_pii`

Use this when you need to scan text for personally identifiable information (PII). Detects emails, phone numbers (international), credit card numbers (with Luhn validation), US SSNs, dates of birth, IP addresses, postal addresses (US/UK/FR), passport numbers, and URLs with tokens. Returns each match with type, redacted value, position, and confidence. Includes overall risk level (low/medium/high/critical). Do NOT use for email validation — use email_verify_address. Do NOT use for GDPR compliance — use compliance_scan_gdpr.

**Parameters**

| Name | Type | Required | Description |
|---|---|---|---|
| `text` | string | yes | Text content to scan for PII |

## Example agent prompts

- "Scan text for personally identifiable information (PII)"

## Payment

- Protocol: [x402](https://x402.org) -- HTTP-native pay-per-call, no signup, no API key
- Network: Base L2 (`eip155:8453`)
- Asset: USDC
- Facilitator: Coinbase CDP (primary), PayAI (fallback)

## Part of klymax402

100 x402 micropayment APIs for AI agents -- one wallet, USDC on Base, zero signup.

- Catalog: https://klymax402.com/llms.txt
- Full API reference: https://klymax402.com/llms-full.txt
- Live stats: https://klymax402.com/stats

## License

MIT
