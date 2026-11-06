# Reads CLOUDFLARE_API_TOKEN from the environment, not Terraform variables/state.
provider "cloudflare" {}

variable "enable_api_ingress" {
  description = "Serve API/origin hosts from the VPS. Organization routing is controlled separately by enable_vps_ingress."
  type        = bool
  default     = true
}

variable "enable_vps_ingress" {
  description = "Cut over API/origin/org hosts to the VPS. Requires verified Ubuntu application readiness, wildcard Origin CA TLS, and the existing dedicated AOP client CA."
  type        = bool
  default     = true
}

locals {
  cloudflare_zone_id = "1631bf4fa13792b9f685ce903875585a"
  # Explicit Worker custom domains must remain on the website when its old
  # wildcard Worker route becomes a no-script (origin-only) route.
  website_hosts = toset(["admin", "docs", "www"])
  # Reserved org slugs from workers/server/src/cache_host.rs. Keep browser
  # protection unchanged on product/staging hosts during the org cutover.
  reserved_hosts = setunion(local.website_hosts, toset([
    "cache", "cache-staging", "api", "auth", "staging", "status", "mail",
    "orgs", "invitations", "default", "nar", "private", "_api", "healthz", "origin",
  ]))
  api_enabled = var.enable_api_ingress || var.enable_vps_ingress
  vps_hosts   = local.api_enabled ? (var.enable_vps_ingress ? toset(["api", "origin", "*"]) : toset(["api", "origin"])) : toset([])
}

resource "cloudflare_ruleset" "api_settings" {
  count       = local.api_enabled ? 1 : 0
  zone_id     = local.cloudflare_zone_id
  name        = "Snowstead API settings"
  description = "API and public-download clients are not browsers; retain website Browser Integrity Check."
  kind        = "zone"
  phase       = "http_config_settings"
  rules = [{
    action = "set_config"
    expression = var.enable_vps_ingress ? format(
      "http.host in {\"api.snowstead.com\" \"origin.snowstead.com\" \"cache.snowstead.com\"} or (ends_with(http.host, \".snowstead.com\") and not http.host in {%s})",
      join(" ", [for host in sort(tolist(local.reserved_hosts)) : jsonencode("${host}.snowstead.com")]),
    ) : "http.host in {\"api.snowstead.com\" \"origin.snowstead.com\" \"cache.snowstead.com\"}"
    description = "Allow non-browser API, org cache, and public-download clients"
    enabled     = true
    action_parameters = {
      bic = false
    }
  }]
}

# Adopt the existing records/settings alongside the approved API-only rollout.
# Keep imports checked in so a fresh operator does not try to create duplicates.
import {
  to = cloudflare_dns_record.orgs_ipv6
  id = "1631bf4fa13792b9f685ce903875585a/46e52b76a6f131810eb3e5ac4d9af77d"
}

import {
  to = cloudflare_workers_route.orgs
  id = "1631bf4fa13792b9f685ce903875585a/8c27e658409748f8a084e61ec83076e8"
}

import {
  to = cloudflare_zone_setting.ssl
  id = "1631bf4fa13792b9f685ce903875585a/ssl"
}

import {
  to = cloudflare_tiered_cache.smart
  id = "1631bf4fa13792b9f685ce903875585a"
}

import {
  to = cloudflare_ruleset.public_cache
  id = "zones/1631bf4fa13792b9f685ce903875585a/b541c1cb666d4ca49d9fe0a6bb59ef47"
}

import {
  to = cloudflare_authenticated_origin_pulls_settings.origin
  id = "1631bf4fa13792b9f685ce903875585a"
}

resource "cloudflare_dns_record" "orgs_ipv6" {
  zone_id = local.cloudflare_zone_id
  name    = "*.snowstead.com"
  type    = "AAAA"
  content = var.enable_vps_ingress ? digitalocean_droplet.service.ipv6_address : "100::"
  comment = var.enable_vps_ingress ? "Org cache hosts served directly by the Snowstead VPS" : "Owner cache hosts served by the snowstead-web wildcard Worker route"
  proxied = true
  ttl     = 1
}

resource "cloudflare_dns_record" "vps_ipv4" {
  for_each = local.vps_hosts
  zone_id  = local.cloudflare_zone_id
  name     = "${each.key}.snowstead.com"
  type     = "A"
  content  = digitalocean_droplet.service.ipv4_address
  proxied  = true
  ttl      = 1
}

resource "cloudflare_dns_record" "vps_ipv6" {
  for_each = setsubtract(local.vps_hosts, toset(["*"]))
  zone_id  = local.cloudflare_zone_id
  name     = "${each.key}.snowstead.com"
  type     = "AAAA"
  content  = digitalocean_droplet.service.ipv6_address
  proxied  = true
  ttl      = 1
}

resource "cloudflare_workers_route" "website" {
  for_each = var.enable_vps_ingress ? local.website_hosts : toset([])
  zone_id  = local.cloudflare_zone_id
  pattern  = "${each.key}.snowstead.com/*"
  script   = "snowstead-web"
}

resource "cloudflare_workers_route" "public_cache" {
  count   = local.api_enabled ? 1 : 0
  zone_id = local.cloudflare_zone_id
  pattern = "cache.snowstead.com/*"
  # Public API reads redirect here. Bypass the website wildcard so the
  # existing R2 custom domain serves them; the legacy /_api/* route still wins.
  script = null
}

resource "cloudflare_workers_route" "api" {
  for_each = local.api_enabled ? toset(["api", "origin"]) : toset([])
  zone_id  = local.cloudflare_zone_id
  pattern  = "${each.key}.snowstead.com/*"
  script   = null

  depends_on = [
    cloudflare_dns_record.vps_ipv4,
    cloudflare_dns_record.vps_ipv6,
    cloudflare_zone_setting.ssl,
    cloudflare_authenticated_origin_pulls_settings.origin,
  ]
}

resource "cloudflare_workers_route" "orgs" {
  zone_id = local.cloudflare_zone_id
  pattern = "*.snowstead.com/*"
  # No script explicitly bypasses Workers. DNS alone does not bypass a route.
  script = var.enable_vps_ingress ? null : "snowstead-web"

  depends_on = [
    cloudflare_dns_record.orgs_ipv6,
    cloudflare_dns_record.vps_ipv4,
    cloudflare_dns_record.vps_ipv6,
    cloudflare_workers_route.website,
    cloudflare_ruleset.api_settings,
    cloudflare_zone_setting.ssl,
    cloudflare_authenticated_origin_pulls_settings.origin,
  ]
}

resource "cloudflare_zone_setting" "ssl" {
  zone_id    = local.cloudflare_zone_id
  setting_id = "ssl"
  value      = local.api_enabled ? "strict" : "full"
}

# Adopt the Smart Tiered Cache topology already enabled in the dashboard.
# This changes cache topology, not which responses are eligible for caching.
resource "cloudflare_tiered_cache" "smart" {
  zone_id = local.cloudflare_zone_id
  value   = "on"
}

# Keep policy/authentication on Rust. Only anonymous public bucket objects may
# use the CDN; legacy public metadata retains its existing origin-defined TTL.
resource "cloudflare_ruleset" "public_cache" {
  zone_id     = local.cloudflare_zone_id
  name        = "default"
  description = "Public cache delivery with explicit API and private bypasses"
  kind        = "zone"
  phase       = "http_request_cache_settings"
  rules = [
    {
      ref         = "snowstead_origin_bypass"
      description = "Never CDN-cache API, org ingress, or other cache-host responses"
      expression = format(
        "http.host in {\"api.snowstead.com\" \"origin.snowstead.com\" \"cache.snowstead.com\"} or (ends_with(http.host, \".snowstead.com\") and not http.host in {%s})",
        join(" ", [for host in sort(tolist(local.reserved_hosts)) : jsonencode("${host}.snowstead.com")]),
      )
      action            = "set_cache_settings"
      enabled           = true
      action_parameters = { cache = false }
    },
    {
      ref         = "a01feaf52fc147ac921c01b898299baf"
      description = "Cache anonymous public NARs and legacy public metadata using origin headers"
      expression = join(" and ", [
        "http.host eq \"cache.snowstead.com\"",
        "http.request.method in {\"GET\" \"HEAD\"}",
        "not has_key(http.request.headers, \"authorization\")",
        "not has_key(http.request.headers, \"cookie\")",
        "not starts_with(http.request.uri.path, \"/_api/\")",
        "not starts_with(http.request.uri.path, \"/private/\")",
        "((starts_with(http.request.uri.path, \"/nar/\") and ends_with(http.request.uri.path, \".nar\")) or ends_with(http.request.uri.path, \".narinfo\") or ends_with(http.request.uri.path, \"/nix-cache-info\"))",
      ])
      action  = "set_cache_settings"
      enabled = true
      action_parameters = {
        cache       = true
        browser_ttl = { mode = "respect_origin" }
        edge_ttl = {
          mode = "bypass_by_default"
          status_code_ttl = [{
            status_code_range = { from = 300, to = 599 }
            value             = -1
          }]
        }
      }
    },
  ]
}

# This is the dedicated, already-uploaded zone client certificate, not the
# global shared Cloudflare AOP certificate (zone setting tls_client_auth).
# Its CA must match /etc/snowstead/origin-client-ca on nginx before cutover.
# Certificate/private-key creation and rotation stay outside Terraform state.
resource "cloudflare_authenticated_origin_pulls_settings" "origin" {
  zone_id = local.cloudflare_zone_id
  enabled = local.api_enabled
}
