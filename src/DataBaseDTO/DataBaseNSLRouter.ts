export const NSL_ROUTER_COLLECTION = "nsl-router";
export interface NSLRouterData {
    serverDomain: string;
    domainName: string;
    publicKey: string;

    // Target port where Caddy listens for incoming traffic (default: 443)
    targetPort?: number;

    // Heartbeat / online status
    lastSeenOnline?: string;

    // Last route registration timestamp (ISO format) - updated on POST /routes
    lastRouteRegistration?: string;

    //meta
    id?: string;
    createdate?: string;
    createdby?: string;
    lastupdate?: string;
    updatedby?: string;
}