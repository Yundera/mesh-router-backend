import cors from "cors";
import cron from "node-cron";
import express from "express";

import {initializeFb} from "./firebase/firebaseIntegration.js";
import {initializeCA} from "./services/CertificateAuthority.js";
import {routerAPI} from "./services/RouterAPI.js";
import {runCleanup} from "./services/DomainCleanup.js";
import {getCleanupCronSchedule} from "./configuration/config.js";
import {startDnsReconciler} from "./services/DnsZones.js";
import {startGatewayCerts} from "./services/GatewayCerts.js";

import 'dotenv/config';

const expressApp = express();
expressApp.use(express.json());
expressApp.use(cors());

const port = 8192;
expressApp.listen(port, async () => {
    initializeFb();
    await initializeCA();
    routerAPI(expressApp);

    // Schedule domain cleanup cron job
    const cronSchedule = getCleanupCronSchedule();
    cron.schedule(cronSchedule, async () => {
        console.log('Running scheduled domain cleanup...');
        try {
            const result = await runCleanup();
            console.log(`Scheduled cleanup complete: ${result.releasedCount} domains released`);
        } catch (error) {
            console.error('Scheduled domain cleanup failed:', error);
        }
    });
    console.log(`Domain cleanup scheduled: ${cronSchedule}`);

    // Nameserver hidden primary (off unless PDNS_API_URL and DNS_IP_ZONE are set)
    startDnsReconciler();
    // Gateway certificates for delegated users (off unless GATEWAY_ACME_DIRECTORY is set)
    startGatewayCerts();

    console.log('Listening on ' + port);
});
