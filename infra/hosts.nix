{
  # Credentials, production migration, and small-host checks passed for staging.
  # Production inventory remains a placeholder; staging is the provisioned VPS.
  staging = {
    deploymentReady = true;
    hostname = "origin.snowstead.com";
    publicHostname = "api.snowstead.com";
    cacheHostSuffix = "snowstead.com";
    address = "100.106.179.40"; # Tailscale; public SSH is closed.
    databaseMaxConnections = 20;
    memoryHigh = "192M";
    memoryMax = "256M";
    resourceLimits = {
      UPLOAD_BUFFER_MIB = 32;
      MAX_UPLOAD_PART_MIB = 16;
      MAX_ACTIVE_VERIFICATIONS = 1;
    };
  };
  production = {
    deploymentReady = false;
    hostname = "production-origin.invalid";
    publicHostname = "production-cache.invalid";
    cacheHostSuffix = "snowstead.com";
    address = "production.invalid";
    databaseMaxConnections = 8;
    memoryHigh = "5G";
    memoryMax = "6G";
  };
}
