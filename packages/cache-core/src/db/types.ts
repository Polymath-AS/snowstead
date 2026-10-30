import type { InferSelectModel } from "drizzle-orm";
import type {
	orgs,
	orgApiKeys,
	caches,
	cacheProtocols,
	blobObjects,
	publishedPaths,
	uploadSessions,
	uploadParts,
	gcMarks,
	apiTokens,
	auditLogs,
} from "./schema.js";

export type Org = InferSelectModel<typeof orgs>;

export type OrgApiKey = InferSelectModel<typeof orgApiKeys>;

export type Cache = InferSelectModel<typeof caches> & {
	protocols: InferSelectModel<typeof cacheProtocols>["protocol"][];
};

export type BlobObject = InferSelectModel<typeof blobObjects>;

export type PublishedPath = InferSelectModel<typeof publishedPaths>;

export type UploadSession = InferSelectModel<typeof uploadSessions>;

export type UploadPart = InferSelectModel<typeof uploadParts>;

export type GcMark = InferSelectModel<typeof gcMarks>;

export type ApiToken = InferSelectModel<typeof apiTokens>;

export type AuditLog = InferSelectModel<typeof auditLogs>;

export type TokenPermission = "pull" | "push" | "go:read" | "go:write";

export type UploadSessionStatus = "pending" | "uploading" | "streaming" | "finalizing" | "aborted" | "completed" | "expired";
