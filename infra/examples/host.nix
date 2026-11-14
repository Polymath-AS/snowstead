{
  # Example only. Copy and configure explicitly before using a real host.
  deploymentReady = false;
  hostname = "origin.example.test";
  publicHostname = "cache.example.test";
  cacheHostSuffix = "example.test";
  address = "host.example.test";
  databaseMaxConnections = 8;
  memoryHigh = "192M";
  memoryMax = "256M";
  resourceLimits = {
    UPLOAD_BUFFER_MIB = 32;
    MAX_UPLOAD_PART_MIB = 16;
    MAX_ACTIVE_VERIFICATIONS = 1;
  };
}
