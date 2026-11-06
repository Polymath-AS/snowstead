terraform {
  required_version = ">= 1.6"
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.28.1"
    }
  }
}

# Reads DIGITALOCEAN_TOKEN from the process environment, never from state.
provider "digitalocean" {}

locals {
  # Shared with the host firewall; refresh from https://www.cloudflare.com/ips/.
  cloudflare_ips = jsondecode(file("${path.module}/../cloudflare-ips.json"))
}

variable "ssh_source_addresses" {
  description = "Temporary public SSH bootstrap CIDRs. Empty after Tailscale enrollment; SSH then uses the tailnet only."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for cidr in var.ssh_source_addresses : can(cidrhost(cidr, 0)) && !contains(["0.0.0.0/0", "::/0"], cidr)])
    error_message = "Use explicit bootstrap CIDRs or an empty list; unrestricted public SSH is not allowed."
  }
}

resource "digitalocean_project" "snowstead" {
  name        = "snowstead-service"
  description = "Snowstead VPS rollout; existing Workers and DNS remain separate."
  purpose     = "Service or API"
  environment = "Staging"
}

# The supplied public key already exists in this account. Reference it without
# taking ownership of a shared SSH key or creating a duplicate.
data "digitalocean_ssh_key" "operator" {
  name = "solidus-operator"
}

resource "digitalocean_droplet" "service" {
  name       = "snowstead-service-fra1"
  region     = "fra1"
  size       = "s-1vcpu-512mb-10gb"
  image      = "ubuntu-24-04-x64"
  ssh_keys   = [data.digitalocean_ssh_key.operator.fingerprint]
  ipv6       = true
  monitoring = true
  backups    = false
  # Install the client, but never put its enrollment key in cloud-init/state.
  user_data = <<-CLOUDINIT
    #cloud-config
    ssh_pwauth: false
    package_update: true
    packages:
      - curl
      - ca-certificates
    runcmd:
      - [sh, -c, 'curl --fail --silent --show-error --location https://tailscale.com/install.sh -o /run/install-tailscale.sh && sh /run/install-tailscale.sh && rm /run/install-tailscale.sh']
  CLOUDINIT

  lifecycle {
    prevent_destroy = true
  }
}

resource "digitalocean_project_resources" "service" {
  project   = digitalocean_project.snowstead.id
  resources = [digitalocean_droplet.service.urn]
}

resource "digitalocean_firewall" "service" {
  name        = "snowstead-service"
  droplet_ids = [digitalocean_droplet.service.id]

  dynamic "inbound_rule" {
    for_each = length(var.ssh_source_addresses) > 0 ? [var.ssh_source_addresses] : []
    content {
      protocol         = "tcp"
      port_range       = "22"
      source_addresses = inbound_rule.value
    }
  }
  inbound_rule {
    protocol         = "udp"
    port_range       = "41641"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = concat(local.cloudflare_ips.ipv4_cidrs, local.cloudflare_ips.ipv6_cidrs)
  }
  inbound_rule {
    protocol         = "icmp"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

output "ipv4_address" {
  value = digitalocean_droplet.service.ipv4_address
}

output "ipv6_address" {
  value = digitalocean_droplet.service.ipv6_address
}
