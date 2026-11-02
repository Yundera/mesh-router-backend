import { after } from "mocha";
import { closeRedisClient } from "../redis/redisClient.js";

// Root hook (top level, outside any describe): runs once after every spec file. The
// Redis client is a shared singleton that a spec may reopen after another closed it,
// so the last open connection would keep mocha alive after the run. Closing it here
// lets the process exit on its own, without --exit.
after(async () => {
  await closeRedisClient();
});
