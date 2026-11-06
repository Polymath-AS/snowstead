let
  operator = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKYZX17OSEH3mKJsP4oFuaGtr8F5TF/3/RXOCw2cBgps";
  # Preserve this host identity through installation; otherwise re-encrypt.
  staging = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHtYCuplCKyKQ+OIFBWDGtSMB7JIThKdxhKXYxMxllG0";
in
builtins.listToAttrs (
  map
    (name: {
      name = "${name}.age";
      value.publicKeys = [
        operator
        staging
      ];
    })
    [
      "environment"
      "migration"
      "origin-certificate"
      "origin-key"
      "origin-client-ca"
    ]
)
