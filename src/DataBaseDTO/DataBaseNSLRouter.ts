export const NSL_ROUTER_COLLECTION = "nsl-router";
export interface NSLRouterData {
    serverDomain: string;
    domainName: string;
    publicKey: string;

    // Target port where Caddy listens for incoming traffic (default: 443)
    targetPort?: number;

    // Last route registration timestamp (ISO format) - updated on POST /routes
    // Also used as online status indicator (replaces deprecated lastSeenOnline)
    lastRouteRegistration?: string;

    //meta
    id?: string;
    createdate?: string;
    createdby?: string;
    lastupdate?: string;
    updatedby?: string;
}