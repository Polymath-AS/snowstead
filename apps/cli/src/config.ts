import { readFile, writeFile, mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

interface ServerConfig {
  readonly server: string;
  readonly token: string;
}

interface HeliosConfig {
  readonly defaultServer?: string;
  readonly servers: Record<string, ServerConfig>;
}

const CONFIG_DIR = join(homedir(), ".config", "helios");
const CONFIG_PATH = join(CONFIG_DIR, "config.json");

export async function loadConfig(): Promise<HeliosConfig> {
  try {
    const raw = await readFile(CONFIG_PATH, "utf-8");
    return JSON.parse(raw);
  } catch {
    return { servers: {} };
  }
}

export async function saveConfig(config: HeliosConfig): Promise<void> {
  await mkdir(CONFIG_DIR, { recursive: true });
  await writeFile(CONFIG_PATH, JSON.stringify(config, null, 2) + "\n", {
    mode: 0o600,
  });
}

export async function login(
  name: string,
  server: string,
  token: string,
): Promise<void> {
  const config = await loadConfig();
  const servers = { ...config.servers, [name]: { server, token } };
  await saveConfig({ ...config, defaultServer: name, servers });
}

export async function getServer(
  name?: string,
): Promise<ServerConfig> {
  const config = await loadConfig();
  const key = name ?? config.defaultServer;
  if (!key) {
    throw new Error("No server specified and no default configured. Run: helios login <name> <url> <token>");
  }
  const entry = config.servers[key];
  if (!entry) {
    throw new Error(`Server '${key}' not found in config. Run: helios login <name> <url> <token>`);
  }
  return entry;
}
