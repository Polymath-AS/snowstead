import gateway from "../../../workers/gateway/src/index.js";
import nix from "../../../workers/nix/src/index.js";
import control from "../../../workers/control/src/index.js";
import go from "../../../workers/go/src/index.js";

export { UploadCoordinator } from "../src/upload-coordinator.js";

// In-process composition lets fixtures override secrets and outbound fetch.
// integration/worker-split.mjs additionally exercises real service bindings.
export default {
	fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		return gateway.fetch(request, {
			NIX: { fetch: (request: Request) => nix.fetch(request, env, ctx) } as Fetcher,
			GO: { fetch: (request: Request) => go.fetch(request, env, ctx) } as Fetcher,
			CONTROL: { fetch: (request: Request) => control.fetch(request, env, ctx) } as Fetcher,
		});
	},
};
