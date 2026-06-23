/**
 * mesh-usage reset-link <email> [--json]
 *
 * Generate a Firebase password-reset link for a user and print it, WITHOUT
 * sending any email. Use this when the reset mail is stuck in the mail queue
 * and you want to hand the link to the user directly.
 *
 * The link is byte-for-byte equivalent to the one the dashboard would email
 * (mesh-dashboard UserApiHandler.handlePasswordReset → generatePasswordResetLink
 * with no ActionCodeSettings, i.e. Firebase's default hosted reset page). It is
 * one-time-use and expires — generating a new one invalidates older ones.
 *
 * Runs inside the backend container, which is configured with the same Firebase
 * project (service account) as the dashboard, so the link is valid for that
 * user pool.
 */
import admin from "firebase-admin";
import { initializeFb } from "../firebase/firebaseIntegration.js";
import { positionals, hasFlag } from "../cli/format.js";

export async function main(argv: string[]): Promise<void> {
  const email = positionals(argv)[0];
  const json = hasFlag(argv, "json");

  if (!email) {
    throw new Error("usage: mesh-usage reset-link <email> [--json]");
  }

  initializeFb();

  let link: string;
  try {
    link = await admin.auth().generatePasswordResetLink(email);
  } catch (err: any) {
    if (err?.code === "auth/user-not-found") {
      throw new Error(`no Firebase user with email '${email}'`);
    }
    throw err;
  }

  if (json) {
    console.log(JSON.stringify({ email, link }, null, 2));
    return;
  }
  console.log(link);
}
