export declare const AUDITOR_PACKET_SCHEMA: 'aevesa.auditor-packet/v1';

export declare function buildAuditorPacket(input: object): Record<string, unknown>;
export declare function verifyAuditorPacket(packet: unknown): Record<string, unknown>;
export declare function computeAuditorPacketDigest(packet: object): string;
export declare function buildAuditorPacketDigest(packet: object): string;
