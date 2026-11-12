{
  pkgs,
  serverPackage,
  inventory,
}:
let
  nginxStart = pkgs.writeShellScript "snowstead-nginx" ''
    set -eu
    ${pkgs.coreutils}/bin/cat > "$RUNTIME_DIRECTORY/nginx.conf" <<EOF
    worker_processes 1;
    pid $RUNTIME_DIRECTORY/nginx.pid;
    error_log stderr warn;
    events { worker_connections 1024; }
    http {
      access_log off;
      client_header_buffer_size 1k;
      large_client_header_buffers 2 8k;
      client_header_timeout 10s;
      client_body_temp_path $RUNTIME_DIRECTORY/body;
      proxy_temp_path $RUNTIME_DIRECTORY/proxy;
      fastcgi_temp_path $RUNTIME_DIRECTORY/fastcgi;
      uwsgi_temp_path $RUNTIME_DIRECTORY/uwsgi;
      scgi_temp_path $RUNTIME_DIRECTORY/scgi;
      client_max_body_size 0;
      client_body_timeout 300s;
      send_timeout 300s;
      keepalive_timeout 10s;
      keepalive_requests 100;
      ssl_protocols TLSv1.2 TLSv1.3;
      upstream snowstead {
        server 127.0.0.1:8080;
        keepalive 4;
      }
      server {
        listen 443 ssl default_server;
        listen [::]:443 ssl default_server;
        ssl_reject_handshake on;
        return 444;
      }
      server {
        listen 443 ssl;
        listen [::]:443 ssl;
        server_name ${inventory.hostname} ${inventory.publicHostname}${
          pkgs.lib.optionalString (inventory ? cacheHostSuffix) " *.${inventory.cacheHostSuffix}"
        };
        ssl_certificate $CREDENTIALS_DIRECTORY/origin-certificate;
        ssl_certificate_key $CREDENTIALS_DIRECTORY/origin-key;
        ssl_client_certificate $CREDENTIALS_DIRECTORY/origin-client-ca;
        ssl_verify_client on;
        location / {
          proxy_pass http://snowstead;
          proxy_http_version 1.1;
          proxy_set_header Connection "";
          proxy_set_header Host \$host;
          proxy_set_header X-Forwarded-For \$remote_addr;
          proxy_set_header X-Forwarded-Proto https;
          proxy_request_buffering off;
          proxy_buffering off;
          proxy_buffer_size 16k;
          proxy_buffers 8 16k;
          proxy_connect_timeout 5s;
          proxy_read_timeout 300s;
          proxy_send_timeout 300s;
        }
      }
    }
    EOF
    exec ${pkgs.nginx}/bin/nginx -e stderr -p "$RUNTIME_DIRECTORY/" -c "$RUNTIME_DIRECTORY/nginx.conf"
  '';
  units = pkgs.runCommand "snowstead-units" { } ''
    mkdir -p $out/lib/systemd/system
    cat > $out/lib/systemd/system/snowstead.service <<'EOF'
    [Unit]
    Description=Snowstead cache service
    Wants=network-online.target
    After=network-online.target
    StartLimitIntervalSec=60
    StartLimitBurst=5

    [Service]
    ExecStart=${serverPackage}/bin/snowstead-server
    Environment=LISTEN_ADDR=127.0.0.1:8080
    Environment=DATABASE_MAX_CONNECTIONS=${toString inventory.databaseMaxConnections}
    ${pkgs.lib.concatStringsSep "\n" (
      pkgs.lib.mapAttrsToList (name: value: "Environment=${name}=${toString value}") (
        inventory.resourceLimits or { }
      )
    )}
    Environment=PUBLIC_URL=https://${inventory.publicHostname}
    ${pkgs.lib.optionalString (
      inventory ? cacheHostSuffix
    ) "Environment=CACHE_HOST_SUFFIX=${inventory.cacheHostSuffix}"}
    ${pkgs.lib.optionalString (
      inventory ? cacheHostSuffix
    ) ''Environment="CACHE_CANONICAL_HOSTS=${inventory.publicHostname} ${inventory.hostname}"''}
    Environment=REQUIRE_CACHE_SIGNING_KEYS=true
    Environment=RUST_LOG=info
    Environment=TMPDIR=/run/snowstead
    EnvironmentFile=/etc/snowstead/environment
    User=snowstead
    Group=snowstead
    RuntimeDirectory=snowstead
    RuntimeDirectoryMode=0700
    WorkingDirectory=/run/snowstead
    UMask=0077
    Restart=on-failure
    RestartSec=5
    TimeoutStopSec=120
    MemoryHigh=${inventory.memoryHigh}
    MemoryMax=${inventory.memoryMax}
    MemorySwapMax=64M
    TasksMax=512
    LimitNOFILE=65536
    NoNewPrivileges=yes
    ProtectSystem=strict
    ProtectHome=yes
    PrivateTmp=yes
    PrivateDevices=yes
    ProtectKernelTunables=yes
    ProtectKernelModules=yes
    ProtectControlGroups=yes
    RestrictSUIDSGID=yes
    RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
    CapabilityBoundingSet=

    [Install]
    WantedBy=multi-user.target
    EOF
    cat > $out/lib/systemd/system/snowstead-proxy.service <<'EOF'
    [Unit]
    Description=Snowstead origin TLS proxy
    Wants=network-online.target snowstead.service
    After=network-online.target snowstead.service
    StartLimitIntervalSec=60
    StartLimitBurst=5

    [Service]
    Type=forking
    PIDFile=/run/snowstead-proxy/nginx.pid
    ExecStart=${nginxStart}
    KillSignal=SIGQUIT
    TimeoutStopSec=120
    LoadCredential=origin-certificate:/etc/snowstead/origin-certificate
    LoadCredential=origin-key:/etc/snowstead/origin-key
    LoadCredential=origin-client-ca:/etc/snowstead/origin-client-ca
    User=snowstead-proxy
    Group=snowstead-proxy
    Environment=HOME=/run/snowstead-proxy
    RuntimeDirectory=snowstead-proxy
    UMask=0077
    Restart=on-failure
    RestartSec=5
    LimitNOFILE=65536
    MemoryMax=96M
    MemorySwapMax=32M
    NoNewPrivileges=yes
    ProtectSystem=strict
    ProtectHome=yes
    PrivateTmp=yes
    PrivateDevices=yes
    ProtectKernelTunables=yes
    ProtectKernelModules=yes
    ProtectControlGroups=yes
    RestrictSUIDSGID=yes
    RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
    AmbientCapabilities=CAP_NET_BIND_SERVICE
    CapabilityBoundingSet=CAP_NET_BIND_SERVICE

    [Install]
    WantedBy=multi-user.target
    EOF
  '';
  activate = pkgs.writeShellApplication {
    name = "snowstead-activate";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.systemd
      pkgs.curl
    ];
    text = ''
      if ! ${pkgs.lib.boolToString inventory.deploymentReady}; then
        echo 'Inventory is not ready; refusing application activation.' >&2
        exit 1
      fi
      if [[ $EUID != 0 ]]; then
        echo 'Activation requires root.' >&2
        exit 1
      fi
      # Host users and secrets are provisioned separately. Validate before
      # changing units; no secret content ever enters a Nix derivation.
      id snowstead >/dev/null
      id snowstead-proxy >/dev/null
      for name in environment origin-certificate origin-key origin-client-ca; do
        test -s "/etc/snowstead/$name"
        test "$(stat -c '%u:%a' "/etc/snowstead/$name")" = 0:600
      done
      for unit in snowstead.service snowstead-proxy.service; do
        ln -sfn "${units}/lib/systemd/system/$unit" "/etc/systemd/system/$unit"
      done
      systemctl daemon-reload
      systemctl enable snowstead.service snowstead-proxy.service
      systemctl reset-failed snowstead.service snowstead-proxy.service
      systemctl restart snowstead.service snowstead-proxy.service
      curl --fail --silent --show-error --retry 20 --retry-all-errors \
        --retry-delay 1 --retry-max-time 90 --max-time 5 http://127.0.0.1:8080/healthz
      systemctl is-active --quiet snowstead-proxy.service
    '';
  };
in
pkgs.buildEnv {
  name = "snowstead-service-bundle";
  paths = [
    serverPackage
    units
    activate
  ];
}
