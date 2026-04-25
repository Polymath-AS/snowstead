import type { InferSelectModel } from "drizzle-orm";
import type {
	caches,
	blobObjects,
	publishedPaths,
	uploadSessions,
	uploadParts,
	gcMarks,
	apiTokens,
	auditLogs,
} from "./schema.js";

export type Cache = InferSelectModel<typeof caches>;

export type BlobObject = InferSelectModel<typeof blobObjects>;

export type PublishedPath = InferSelectModel<typeof publishedPaths>;

export type UploadSession = InferSelectModel<typeof uploadSessions>;

export type UploadPart = InferSelectModel<typeof uploadParts>;

export type GcMark = InferSelectModel<typeof gcMarks>;

export type ApiToken = InferSelectModel<typeof apiTokens>;

export type AuditLog = InferSelectModel<typeof auditLogs>;

export type TokenPermission = "pull" | "push";

export type UploadSessionStatus = "pending" | "uploading" | "completed" | "expired";
