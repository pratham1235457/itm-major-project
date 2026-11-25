/*
 * Educational, rule-based prompt-injection detector.
 * This is a heuristic scanner, not a security guarantee or an ML classifier.
 */

const RULES = [
  {
    id: "instruction_override",
    label: "Instruction override attempt",
    severity: "high",
    points: 30,
    patterns: [
      /\b(ignore|disregard|forget|override)\b.{0,60}\b(previous|prior|above|earlier|all)\b.{0,30}\b(instructions?|rules?|prompts?)\b/i,
      /\b(ignore|disregard)\s+(all\s+)?(previous|prior|above)\s+instructions?\b/i,
      /\bnew\s+instructions?\s*:\s*/i
    ],
    explanation: "Attempts to replace or cancel instructions that came before this text."
  },
  {
    id: "role_impersonation",
    label: "Role or authority impersonation",
    severity: "high",
    points: 25,
    patterns: [
      /\b(system|developer)\s*(prompt|message|instruction)\s*:/i,
      /\byou\s+are\s+now\s+(in\s+)?(developer|admin|root|unrestricted)\s+mode\b/i,
      /\bact\s+as\s+(the\s+)?system\b/i,
      /<\|im_start\|>\s*(system|developer)/i
    ],
    explanation: "Tries to impersonate a privileged role or change the assistant's operating mode."
  },
  {
    id: "data_exfiltration",
    label: "Hidden instruction or secret extraction",
    severity: "high",
    points: 25,
    patterns: [
      /\b(reveal|show|print|repeat|disclose|output)\b.{0,50}\b(system prompt|hidden instructions?|internal prompt|secret key|api key|password)\b/i,
      /\bwhat\s+(are|is)\s+your\s+(system prompt|hidden instructions?)\b/i,
      /\bprint\s+.*\benvironment variables\b/i
    ],
    explanation: "Requests hidden prompts, credentials, or other private/internal data."
  },
  {
    id: "safety_bypass",
    label: "Safety bypass language",
    severity: "medium",
    points: 18,
    patterns: [
      /\b(bypass|disable|remove|ignore)\b.{0,40}\b(safety|security|content)\s+(filter|rules?|policy|restrictions?)\b/i,
      /\bwithout\s+(any\s+)?(limitations|restrictions|safeguards)\b/i,
      /\bdo\s+anything\s+now\b/i
    ],
    explanation: "Attempts to bypass safety controls or restrictions."
  },
  {
    id: "tool_misuse",
    label: "Untrusted tool or action request",
    severity: "medium",
    points: 15,
    patterns: [
      /\b(send|forward|email|upload|delete|transfer|purchase)\b.{0,70}\b(without|silently|secretly|approval|permission)\b/i,
      /\bcall\s+(the\s+)?(tool|function|api)\b.{0,60}\b(secretly|without\s+asking)\b/i
    ],
    explanation: "Suggests taking an external action without user approval or normal checks."
  },
  {
    id: "prompt_boundary",
    label: "Suspicious prompt boundary markers",
    severity: "low",
    points: 8,
    patterns: [
      /```[\s\S]{0,500}\b(ignore|override|reveal)\b/i,
      /\[(?:system|developer|assistant)\]/i,
      /<\/?(?:system|instruction|prompt)>/i
    ],
    explanation: "Contains role-like labels or embedded instruction boundaries. These can also appear in harmless examples."
  }
];

function analyzePrompt(input) {
  const findings = [];

  for (const rule of RULES) {
    const matched = rule.patterns.some((pattern) => pattern.test(input));
    if (matched) {
      findings.push({
        id: rule.id,
        label: rule.label,
        severity: rule.severity,
        points: rule.points,
        explanation: rule.explanation
      });
    }
  }

  const score = Math.min(100, findings.reduce((sum, item) => sum + item.points, 0));
  let risk = "Low";
  if (score >= 50) risk = "High";
  else if (score >= 20) risk = "Medium";

  return {
    risk,
    score,
    verdict: risk === "High"
      ? "Potential prompt injection detected"
      : risk === "Medium"
        ? "Suspicious instruction patterns found"
        : "No strong injection patterns detected",
    findings,
    recommendation: findings.length
      ? "Treat this text as untrusted data. Do not let it override trusted system/developer instructions, and require explicit approval before external actions."
      : "No matching rules were found. Continue to treat user-supplied or retrieved text as untrusted; this scanner can miss novel attacks.",
    note: "Heuristic result only. A low score does not prove that a prompt is safe."
  };
}

export default { analyzePrompt, RULES };