/**
 * isYggdrasil reports whether addr is inside 200::/7.
 * addr is the IP text on a flow. IPv4 and unparseable text are false.
 * 2000::/3 and 2002::/16 are outside this prefix.
 */
export function isYggdrasil(addr: string): boolean {
  const bytes = ipv6Bytes(addr);
  if (!bytes) return false;
  return (bytes[0] & 0xfe) === 0x02;
}

/**
 * addressScope is the scope badge for one flow endpoint.
 * addr is the IP text. stored is src_scope or dst_scope from the flow.
 * An address inside 200::/7 is yggdrasil, including when the stored scope
 * is still global. Any other non-global stored scope is shown as stored.
 * Global has no badge. The result is the badge text, or undefined.
 */
export function addressScope(addr: string, stored: string | undefined): string | undefined {
  if (isYggdrasil(addr)) return "yggdrasil";
  if (!stored || stored === "global") return undefined;
  return stored;
}

function ipv6Bytes(addr: string): Uint8Array | null {
  if (addr.includes("%") || !addr.includes(":")) return null;
  const halves = addr.split("::");
  if (halves.length > 2) return null;
  const head = parseGroups(halves[0]);
  if (!head) return null;
  if (halves.length === 1) {
    if (head.length !== 8) return null;
    return groupsToBytes(head);
  }
  const tail = parseGroups(halves[1]);
  if (!tail) return null;
  const missing = 8 - head.length - tail.length;
  if (missing < 1) return null;
  return groupsToBytes([...head, ...new Array<number>(missing).fill(0), ...tail]);
}

function parseGroups(text: string): number[] | null {
  if (text === "") return [];
  const parts = text.split(":");
  const groups: number[] = [];
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (part.includes(".")) {
      if (i !== parts.length - 1) return null;
      const v4 = ipv4Groups(part);
      if (!v4) return null;
      groups.push(v4[0], v4[1]);
      continue;
    }
    if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return null;
    groups.push(Number.parseInt(part, 16));
  }
  return groups;
}

function ipv4Groups(text: string): [number, number] | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  const bytes: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    bytes.push(n);
  }
  return [(bytes[0] << 8) | bytes[1], (bytes[2] << 8) | bytes[3]];
}

function groupsToBytes(groups: number[]): Uint8Array {
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = (groups[i] >> 8) & 0xff;
    bytes[i * 2 + 1] = groups[i] & 0xff;
  }
  return bytes;
}
