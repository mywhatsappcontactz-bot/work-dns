import dnsPacket from 'dns-packet';

export type DnsErrorRcode = 'FORMERR' | 'SERVFAIL' | 'NXDOMAIN' | 'REFUSED';

const RCODE_BITS: Record<DnsErrorRcode, number> = {
  FORMERR: 1,
  SERVFAIL: 2,
  NXDOMAIN: 3,
  REFUSED: 5,
};

/**
 * dns-packet ignores an `rcode` property on encode; the response code is the
 * low 4 bits of `flags`. Echo the query id and questions so clients accept it.
 * (Same helper as apps/gateway/src/dns-response.ts, plus FORMERR.)
 */
export function buildErrorResponse(
  query: Pick<dnsPacket.Packet, 'id' | 'questions' | 'flags'>,
  rcode: DnsErrorRcode
): Buffer {
  const recursionDesired = (query.flags ?? 0) & dnsPacket.RECURSION_DESIRED;
  const packet: dnsPacket.Packet = {
    type: 'response',
    id: query.id ?? 0,
    flags: recursionDesired | dnsPacket.RECURSION_AVAILABLE | RCODE_BITS[rcode],
    questions: query.questions ?? [],
    answers: [],
  };
  return Buffer.from(dnsPacket.encode(packet));
}
