export const NSL_ROUTER_COLLECTION = "nsl-router";
export interface NSLRouterData {
    serverDomain: string;
    domainName: string;
    publicKey: string;

    // Host IP assigned to this user's PCS instance
    hostIp?: string;
    hostIpUpdatedAt?: string;

    // Target port where Caddy listens for incoming traffic (default: 443)
    targetPort?: number;

    // Heartbeat / online status
    lastSeenOnline?: string;

    //meta
    id?: string;
    createdate?: string;
    createdby?: string;
    lastupdate?: string;
    updatedby?: string;
}