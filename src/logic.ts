import type { Hono } from "hono";


// ATXP: requirePayment only fires inside an ATXP context (set by atxpHono middleware).
// For raw x402 requests, the existing @x402/hono middleware handles the gate.
// If neither protocol is active (ATXP_CONNECTION unset), tryRequirePayment is a no-op.
async function tryRequirePayment(price: number): Promise<void> {
  if (!process.env.ATXP_CONNECTION) return;
  try {
    const { requirePayment } = await import("@atxp/server");
    const BigNumber = (await import("bignumber.js")).default;
    await requirePayment({ price: BigNumber(price) });
  } catch (e: any) {
    if (e?.code === -30402) throw e;
  }
}

interface PiiItem {
  type: string;
  value: string;
  redacted: string;
  position: { start: number; end: number };
  confidence: number;
}

interface DetectResult {
  piiFound: boolean;
  piiCount: number;
  items: PiiItem[];
  riskLevel: "low" | "medium" | "high" | "critical";
}

function luhnCheck(num: string): boolean {
  const digits = num.replace(/\D/g, "");
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

function redact(value: string, type: string): string {
  if (value.length <= 4) return "****";
  if (type === "email") {
    const [local, domain] = value.split("@");
    return local[0] + "***@" + domain;
  }
  if (type === "credit_card") return value.slice(0, 4) + " **** **** " + value.slice(-4);
  if (type === "ssn") return "***-**-" + value.slice(-4);
  if (type === "phone") return value.slice(0, 3) + "****" + value.slice(-2);
  if (type === "ip_address") return value.split(".").map((o, i) => (i < 2 ? o : "***")).join(".");
  return value.slice(0, 2) + "*".repeat(value.length - 4) + value.slice(-2);
}

interface Pattern {
  type: string;
  regex: RegExp;
  confidence: number;
  validate?: (match: string) => boolean;
}

const PATTERNS: Pattern[] = [
  { type: "email", regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, confidence: 0.95 },
  { type: "phone", regex: /(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}/g, confidence: 0.8 },
  { type: "phone_international", regex: /\+(?:[1-9]\d{0,2})[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}/g, confidence: 0.85 },
  {
    type: "credit_card",
    regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    confidence: 0.9,
    validate: (m) => luhnCheck(m),
  },
  { type: "ssn", regex: /\b\d{3}-\d{2}-\d{4}\b/g, confidence: 0.9 },
  { type: "date_of_birth", regex: /\b(?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])[-/](?:19|20)\d{2}\b/g, confidence: 0.7 },
  { type: "date_of_birth", regex: /\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b/g, confidence: 0.7 },
  { type: "ip_address", regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, confidence: 0.85 },
  { type: "us_address", regex: /\b\d{1,5}\s+[\w\s]+(?:St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Ln|Lane|Rd|Road|Ct|Court|Way|Pl|Place)\.?(?:,?\s+[\w\s]+,?\s+[A-Z]{2}\s+\d{5}(?:-\d{4})?)\b/gi, confidence: 0.75 },
  { type: "uk_postcode", regex: /\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b/gi, confidence: 0.8 },
  { type: "fr_address", regex: /\b\d{1,4}(?:\s+(?:rue|avenue|boulevard|place|chemin|impasse|allée))\s+[\w\s]+,?\s*\d{5}\s+[\w\s-]+\b/gi, confidence: 0.7 },
  { type: "passport", regex: /\b[A-Z]{1,2}\d{6,9}\b/g, confidence: 0.5 },
  { type: "url_with_token", regex: /https?:\/\/[^\s]+[?&](?:token|key|secret|password|api_key|access_token|auth)=[^\s&]+/gi, confidence: 0.9 },
];

function detectPii(text: string): DetectResult {
  const items: PiiItem[] = [];
  const seen = new Set<string>();

  for (const pattern of PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      const value = match[0];
      const key = `${pattern.type}:${match.index}:${value}`;
      if (seen.has(key)) continue;
      if (pattern.validate && !pattern.validate(value)) continue;
      seen.add(key);
      items.push({
        type: pattern.type,
        value: value,
        redacted: redact(value, pattern.type),
        position: { start: match.index, end: match.index + value.length },
        confidence: pattern.confidence,
      });
    }
  }

  // Deduplicate overlapping matches (keep higher confidence)
  items.sort((a, b) => a.position.start - b.position.start);
  const filtered: PiiItem[] = [];
  for (const item of items) {
    const last = filtered[filtered.length - 1];
    if (last && item.position.start < last.position.end) {
      if (item.confidence > last.confidence) filtered[filtered.length - 1] = item;
    } else {
      filtered.push(item);
    }
  }

  let riskLevel: DetectResult["riskLevel"] = "low";
  const hasCritical = filtered.some((i) => ["credit_card", "ssn", "passport"].includes(i.type));
  const hasHigh = filtered.some((i) => ["email", "phone", "phone_international", "url_with_token"].includes(i.type));
  if (hasCritical) riskLevel = "critical";
  else if (filtered.length >= 5) riskLevel = "high";
  else if (hasHigh || filtered.length >= 2) riskLevel = "medium";

  return {
    piiFound: filtered.length > 0,
    piiCount: filtered.length,
    items: filtered,
    riskLevel,
  };
}

export function registerRoutes(app: Hono) {
  app.post("/api/detect", async (c) => {
    await tryRequirePayment(0.005);
    const body = await c.req.json().catch(() => null);
    if (!body || !body.text) return c.json({ error: "Missing required field: text" }, 400);
    if (typeof body.text !== "string") return c.json({ error: "Field 'text' must be a string" }, 400);

    const result = detectPii(body.text);
    return c.json(result);
  });
}
