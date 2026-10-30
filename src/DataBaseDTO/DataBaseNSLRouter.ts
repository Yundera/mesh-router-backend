export const NSL_ROUTER_COLLECTION = "nsl-router";

/** What the nameserver answers for a user's names (mesh-router-nameserver architecture §4.3). */
export type DnsForce = "auto" | "gateway" | "direct";

/**
 * Nameserver settings for a user (DnsZones.ts). Absent = dormant, auto.
 */
export interface NSLRouterDns {
    // written by the backend: the parent zone delegates <user>.<zone> to our nameservers
    // (seen by public resolvers); absent = dormant (zone served, asked by nobody)
    live?: boolean;
    // whole user: auto = answer rule, gateway = always the gateway, direct = box IP (admin)
    force?: DnsForce;
    // per host label ("immich" for immich.<user>.<zone>), overrides `force`
    hostForce?: Record<string, "gateway" | "direct">;
    // the box's Let's Encrypt account URIs, reported by the box (PUT /dns/v1/caa): the zone's
    // CAA lets only these accounts obtain certificates for the user's names
    caaAccounts?: string[];
}

export interface NSLRouterData {
    serverDomain: string;
    domainName: string;
    publicKey: string;

    // Target port where Caddy listens for incoming traffic (default: 443)
    targetPort?: number;

    // Last route registration timestamp (ISO format) - updated on POST /routes
    // Also used as online status indicator (replaces deprecated lastSeenOnline)
    lastRouteRegistration?: string;

    // Nameserver settings (mesh-router-nameserver); absent on most users
    dns?: NSLRouterDns;

    //meta
    id?: string;
    createdate?: string;
    createdby?: string;
    lastupdate?: string;
    updatedby?: string;
}