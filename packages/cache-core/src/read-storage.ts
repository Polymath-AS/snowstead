/** The read-side contract, implemented by R2 locally and isolated RPC services at the edge. */
export interface ReadBucket {
	get(key: string, options?: { range: { offset: number; length: number } }): Promise<{ size: number; body: ReadableStream<Uint8Array> } | null>;
	head(key: string): Promise<{ size: number } | null>;
}

export const PUBLICATION_KEY = /^v2\/o\/[A-Za-z0-9_-]{1,128}\/c\/[1-9][0-9]*\/e\/[0-9a-f-]{36}\/p\/[0-9abcdfghijklmnpqrsvwxyz]{32}\/r\/[0-9a-f-]{36}\/(nar|narinfo)$/;
