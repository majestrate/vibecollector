/**
 * portText formats the flow-table port cell.
 * src and dst are the stored ports. proto is the IP protocol number.
 * Protocols 1 and 58 store ICMP type and code in the destination port as
 * (type<<8)|code. A non-zero destination port is shown as type.code.
 * A zero destination port stays numeric. That value is also ICMP echo reply,
 * and it is what older v9 rows stored before the type was kept.
 * Other protocols show the two ports separated by an arrow.
 * A missing port is an empty side.
 */
export function portText(
  proto: number | null | undefined,
  src: number | null | undefined,
  dst: number | null | undefined,
): string {
  if ((proto === 1 || proto === 58) && dst !== undefined && dst !== null && dst !== 0) {
    const type = (dst >> 8) & 0xff;
    const code = dst & 0xff;
    const left = src === undefined || src === null ? "" : String(src);
    return `${left}→${type}.${code}`;
  }
  return `${src ?? ""}→${dst ?? ""}`;
}
