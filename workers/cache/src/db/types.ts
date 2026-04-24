import type { InferSelectModel } from "drizzle-orm";
import type {
	caches,
	blobObjects,
	publishedPaths,
	uploadSessions,
	uploadParts,
	gcMarks,
} from "./schema.js";

export type Cache = InferSelectModel<typeof caches>;

export type BlobObject = InferSelectModel<typeof blobObjects>;

export type PublishedPath = InferSelectModel<typeof publishedPaths>;

export type UploadSession = InferSelectModel<typeof uploadSessions>;

export type UploadPart = InferSelectModel<typeof uploadParts>;

export type GcMark = InferSelectModel<typeof gcMarks>;

export type UploadSessionStatus = "pending" | "uploading" | "completed" | "expired";
