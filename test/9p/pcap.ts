/**
 * A pcap file, built in JavaScript, so an outside dissector can read our wire.
 *
 * `test/9p/dissect.test.ts` hands the bytes of a real exchange to `tshark` and
 * asks its 9P dissector — an implementation sharing none of our code — what it
 * thinks they say. `tshark` reads packets, not byte streams, so the exchange
 * has to become a capture file first.
 *
 * Capturing it for real is not an option: a live capture needs `CAP_NET_RAW`,
 * and every Tier-0/Tier-1 test in this repository runs unprivileged. So the
 * capture is *synthesized*: the exchange's real bytes are wrapped in fabricated
 * Ethernet/IPv4/TCP headers and written out in the classic pcap format (the
 * 24-byte global header of `pcap/pcap.h`, then a 16-byte record header per
 * packet). Nothing here touches a socket or a privilege.
 *
 * Two details make the difference between a file `tshark` dissects and one it
 * shrugs at:
 *
 * - **The port.** Wireshark registers the 9P dissector on TCP port 564 (the
 *   IANA assignment for `plan9fs`), so a capture whose server side is 564
 *   dissects with no `-d` flag at all. The test passes one anyway, because a
 *   default is a thing that can change under us and the flag is free.
 * - **The sequence numbers.** A 9P message longer than one segment is only
 *   readable if the receiver can put the segments back together, and `tshark`
 *   reassembles a TCP stream exactly the way a kernel does — by sequence
 *   number. So the numbers here are real: each direction starts at its own ISN,
 *   the SYN consumes one, and every segment advances the sender's sequence by
 *   its payload length while acknowledging everything the peer has sent. That
 *   is what lets the test deliberately cut a message in half and still expect
 *   the dissector to read it whole.
 *
 * The checksums are computed rather than zeroed. `tshark` does not verify them
 * by default, but "no expert-info errors anywhere in the capture" is one of the
 * things the test asserts, and a capture that is correct in every respect makes
 * that assertion mean what it says.
 *
 * Deterministic by construction: fixed MAC addresses, fixed IPs, fixed ISNs,
 * and timestamps that count up from a fixed epoch. The same exchange always
 * produces the same file.
 */

/** One TCP segment: bytes, and which end of the conversation sent them. */
export interface P9Delivery {
  /** `"client"` for a request stream segment, `"server"` for a reply one. */
  from: "client" | "server";
  /** The payload. May be a whole 9P message, part of one, or several. */
  bytes: Uint8Array;
}

/** What to fabricate around the payloads. */
export interface PcapOptions {
  /** The client's ephemeral port. Default `40404`. */
  clientPort?: number;
  /** The server's port. Default `564`, where the 9P dissector already lives. */
  serverPort?: number;
}

/** IANA's `plan9fs`, and where Wireshark's 9P dissector registers itself. */
export const P9_TCP_PORT = 564;

/** LINKTYPE_ETHERNET, the `network` field of the pcap global header. */
const LINKTYPE_ETHERNET = 1;

/** `0xa1b2c3d4` written natively means "this file is host-endian, µs stamps". */
const PCAP_MAGIC = 0xa1_b2_c3_d4;

/** Locally-administered unicast MACs — the `02:` prefix, no vendor implied. */
const CLIENT_MAC = Uint8Array.from([0x02, 0, 0, 0, 0, 0x01]);
const SERVER_MAC = Uint8Array.from([0x02, 0, 0, 0, 0, 0x02]);

/** RFC 5737 says `192.0.2.0/24` is for documentation. This is documentation. */
const CLIENT_IP = Uint8Array.from([192, 0, 2, 1]);
const SERVER_IP = Uint8Array.from([192, 0, 2, 2]);

/** Initial sequence numbers. Distinct and unmistakable in a hex dump. */
const CLIENT_ISN = 0x10_00_00_00;
const SERVER_ISN = 0x20_00_00_00;

/** The first packet's timestamp: 2026-07-29T00:00:00Z, and then one ms apart. */
const FIRST_SECOND = 1_784_073_600;

const ETHERTYPE_IPV4 = 0x08_00;
const IPPROTO_TCP = 6;

const TCP_FIN = 0x01;
const TCP_SYN = 0x02;
const TCP_ACK = 0x10;
const TCP_PSH = 0x08;

/**
 * The largest payload one fabricated segment carries.
 *
 * A plain Ethernet MSS: 1500 bytes of MTU less 20 of IPv4 and 20 of TCP. A
 * delivery longer than this becomes several segments, exactly as it would have
 * on a wire — which is one of the two ways a 9P message here ends up split.
 */
const MAX_SEGMENT = 1460;

/**
 * The internet checksum (RFC 1071): ones-complement sum of 16-bit words,
 * complemented. Used for both the IPv4 header and the TCP pseudo-header sum.
 */
function checksum(parts: readonly Uint8Array[]): number {
  let sum = 0;
  for (const part of parts) {
    let index = 0;
    for (; index + 1 < part.length; index += 2) {
      sum += (part[index]! << 8) | part[index + 1]!;
    }
    if (index < part.length) {
      // An odd-length part is padded on the right with a zero byte.
      sum += part[index]! << 8;
    }
  }
  while (sum > 0xff_ff) {
    sum = (sum & 0xff_ff) + (sum >>> 16);
  }
  return ~sum & 0xff_ff;
}

/** One direction's running state. */
interface Endpoint {
  mac: Uint8Array;
  ip: Uint8Array;
  port: number;
  /** The next sequence number this end will send. */
  seq: number;
}

/** Sequence numbers are 32-bit and wrap; keep them unsigned. */
function advance(seq: number, by: number): number {
  return (seq + by) >>> 0;
}

/** Ethernet + IPv4 + TCP around `payload`, checksums filled in. */
function frame(from: Endpoint, to: Endpoint, flags: number, payload: Uint8Array): Uint8Array {
  const ip = new Uint8Array(20);
  const ipView = new DataView(ip.buffer);
  ip[0] = 0x45; // IPv4, 5 words of header.
  ipView.setUint16(2, 20 + 20 + payload.length);
  ipView.setUint16(4, 0); // Identification. Fixed: nothing here fragments.
  ipView.setUint16(6, 0x40_00); // Don't fragment.
  ip[8] = 64; // TTL.
  ip[9] = IPPROTO_TCP;
  ip.set(from.ip, 12);
  ip.set(to.ip, 16);
  ipView.setUint16(10, checksum([ip]));

  const tcp = new Uint8Array(20);
  const tcpView = new DataView(tcp.buffer);
  tcpView.setUint16(0, from.port);
  tcpView.setUint16(2, to.port);
  tcpView.setUint32(4, from.seq);
  // A SYN has nothing to acknowledge; everything after it acknowledges the
  // peer's whole stream so far.
  tcpView.setUint32(8, (flags & TCP_ACK) === 0 ? 0 : to.seq);
  tcp[12] = 5 << 4; // Data offset: 5 words, no options.
  tcp[13] = flags;
  tcpView.setUint16(14, 0xff_ff); // Window. Large enough to never gate anything.

  // The TCP checksum covers a pseudo-header of the addresses, the protocol and
  // the segment length, then the header and the payload.
  const pseudo = new Uint8Array(12);
  pseudo.set(from.ip, 0);
  pseudo.set(to.ip, 4);
  pseudo[9] = IPPROTO_TCP;
  new DataView(pseudo.buffer).setUint16(10, 20 + payload.length);
  tcpView.setUint16(16, checksum([pseudo, tcp, payload]));

  const ethernet = new Uint8Array(14);
  ethernet.set(to.mac, 0);
  ethernet.set(from.mac, 6);
  new DataView(ethernet.buffer).setUint16(12, ETHERTYPE_IPV4);

  const packet = new Uint8Array(ethernet.length + ip.length + tcp.length + payload.length);
  packet.set(ethernet, 0);
  packet.set(ip, ethernet.length);
  packet.set(tcp, ethernet.length + ip.length);
  packet.set(payload, ethernet.length + ip.length + tcp.length);
  return packet;
}

/** The 16-byte per-packet record header, then the packet. */
function record(index: number, packet: Uint8Array): Uint8Array {
  const out = new Uint8Array(16 + packet.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, FIRST_SECOND + Math.floor(index / 1000), true);
  view.setUint32(4, (index % 1000) * 1000, true);
  view.setUint32(8, packet.length, true); // Captured length.
  view.setUint32(12, packet.length, true); // Original length: nothing is cut.
  out.set(packet, 16);
  return out;
}

/**
 * Cut one delivery into segments of at most {@link MAX_SEGMENT} bytes.
 *
 * This is the only splitting this file does. A caller that wants a *particular*
 * message split — the reassembly cases — hands the two halves in as two
 * deliveries, which is why there is no limit parameter here to get out of step
 * with the one the header arithmetic assumes.
 */
function segment(bytes: Uint8Array): Uint8Array[] {
  const parts: Uint8Array[] = [];
  for (let at = 0; at < bytes.length; at += MAX_SEGMENT) {
    parts.push(bytes.subarray(at, Math.min(at + MAX_SEGMENT, bytes.length)));
  }
  return parts;
}

/**
 * A capture file holding `deliveries`, in the order given.
 *
 * A three-way handshake opens it and a FIN exchange closes it, so the file is a
 * whole TCP conversation rather than a fragment picked up mid-stream.
 */
export function buildPcap(
  deliveries: readonly P9Delivery[],
  options: PcapOptions = {},
): Uint8Array {
  const client: Endpoint = {
    mac: CLIENT_MAC,
    ip: CLIENT_IP,
    port: options.clientPort ?? 40_404,
    seq: CLIENT_ISN,
  };
  const server: Endpoint = {
    mac: SERVER_MAC,
    ip: SERVER_IP,
    port: options.serverPort ?? P9_TCP_PORT,
    seq: SERVER_ISN,
  };

  const packets: Uint8Array[] = [];
  const empty = new Uint8Array(0);

  // Handshake. A SYN consumes one sequence number, which is why both ends
  // advance by one without sending a byte.
  packets.push(frame(client, server, TCP_SYN, empty));
  client.seq = advance(client.seq, 1);
  packets.push(frame(server, client, TCP_SYN | TCP_ACK, empty));
  server.seq = advance(server.seq, 1);
  packets.push(frame(client, server, TCP_ACK, empty));

  for (const delivery of deliveries) {
    if (delivery.bytes.length === 0) {
      continue;
    }
    const [from, to] = delivery.from === "client" ? [client, server] : [server, client];
    for (const part of segment(delivery.bytes)) {
      packets.push(frame(from, to, TCP_PSH | TCP_ACK, part));
      from.seq = advance(from.seq, part.length);
    }
  }

  // Teardown, so the conversation is complete and nothing is left half-open.
  packets.push(frame(client, server, TCP_FIN | TCP_ACK, empty));
  client.seq = advance(client.seq, 1);
  packets.push(frame(server, client, TCP_FIN | TCP_ACK, empty));
  server.seq = advance(server.seq, 1);
  packets.push(frame(client, server, TCP_ACK, empty));

  const header = new Uint8Array(24);
  const view = new DataView(header.buffer);
  view.setUint32(0, PCAP_MAGIC, true);
  view.setUint16(4, 2, true); // Major version.
  view.setUint16(6, 4, true); // Minor version.
  view.setUint32(8, 0, true); // GMT offset.
  view.setUint32(12, 0, true); // Timestamp accuracy, unused by everyone.
  view.setUint32(16, 0xff_ff, true); // Snap length.
  view.setUint32(20, LINKTYPE_ETHERNET, true);

  const records = packets.map((packet, index) => record(index, packet));
  const total = records.reduce((sum, one) => sum + one.length, header.length);
  const file = new Uint8Array(total);
  file.set(header, 0);
  let at = header.length;
  for (const one of records) {
    file.set(one, at);
    at += one.length;
  }
  return file;
}
