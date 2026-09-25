/** One run of an attribution line: plain text, or a link written as `[text](https://...)` in catalog/layers.yaml. */
export interface AttributionPart {
  text: string;
  href?: string;
}

const LINK = /\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g;

/** Splits a layer's attribution into text and links. Only http(s) targets become links; anything else stays text. */
export function parseAttribution(line: string): AttributionPart[] {
  const parts: AttributionPart[] = [];
  let last = 0;
  for (const m of line.matchAll(LINK)) {
    if (m.index > last) parts.push({ text: line.slice(last, m.index) });
    parts.push({ text: m[1]!, href: m[2]! });
    last = m.index + m[0].length;
  }
  if (last < line.length) parts.push({ text: line.slice(last) });
  return parts;
}
