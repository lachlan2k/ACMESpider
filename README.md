# ACMESpider

ACMESpider acts as a broker within your network to issue trusted ACME certificates for internal servers.

Your internal services complete an internal HTTP-01 ACME challenge with ACMESpider, and ACMESpider uses a DNS-01 challenge to provision a certificate from an authority such as Let's Encrypt.

![image](https://github.com/user-attachments/assets/833963b4-73aa-433c-8ac8-4b61d7917077)

## Why?

Traditionally, the two most common methods to leverage a public ACME server (such as Let's Encrypt) for internal services are to:
- Use DNS-01 challenges, or;
- Expose the service to the public internet for HTTP-01 challenges (at least the `.well-known/acme-challenge` path)

However both of these methods are incovienient and sacrifice security:
- Using DNS-01 requires storing an API key for your DNS provider on every server that uses ACME
- DNS-01 challenges typically allow the server to provision a certificate for any subdomain
- Publicly exposing services increases attack surface and makes network segmentation more challenging
- Not every DNS provider is support

ACMESpider solves these problems:
- DNS API credentials are only stored on ACMESpider, and don't have to be littered around all your servers
- Logging of internally issued certificate is centralised on ACMESpider
- You don't have to expose anything to the public internet
- Internal services don't have to communicate to the internet - only to ACMESpider
- ACMESpider supports a very wide range of DNS providers


## Deployment

```
docker run \
    -d \
    -p 443:443 \
    --name acmespider \
    -v acmespider_data:/data \
    -e ACMESPIDER_HOSTNAME=acmespider.internal.example.com \
    -e ACMESPIDER_ACME_EMAIL=<YOUR EMAIL HERE> \
    -e ACMESPIDER_ACME_TOS_ACCEPT=true \
    -e CLOUDFLARE_DNS_API_TOKEN=<YOUR CLOUDFLARE API TOKEN> \
    -e CLOUDFLARE_ZONE_API_TOKEN=<YOUR CLOUDFLARE API TOKEN> \
    ghcr.io/lachlan2k/acmespider:latest
```

### Prerequisites

- **Public Domain:** ACMESpider is designed to provision certificates from a public authority like Let's Encrypt using a public domain name that you own (such as `example.com`), with internal services on subdomains, for instance, `wiki.internal.example.com`, `photos.internal.example.com`, etc.
- **Supported DNS Provider:** ACMESpider leverages [Lego](https://go-acme.github.io/lego/dns/) to provision certificates. To complete your public DNS challenge, your domain will need to be connected to any DNS provider supported by Lego, such as Cloudflare, Route53, Azure DNS, and many others. You will need an API token or similar for your provider.
- **Appropriate DNS Records:** ACMESpider needs to reach your internal services by their hostname to complete HTTP-01 challenges. Whether you use [split-horizon DNS](https://en.wikipedia.org/wiki/Split-horizon_DNS) or configure your records with public DNS, one way or another, your ACMESpider server will need to resolve your service's hostname to their private IP address.
    - ACMESpider itself also uses the same provider to issue certificates for itself. You will require a DNS record such as `acmespider.internal.example.com` that points to your ACMESpider server.

### Environment Variables

You must configure one Lego DNS provider with environment variables. See [here](https://go-acme.github.io/lego/dns/). For example, `CLOUDFLARE_DNS_API_TOKEN` and `CLOUDFLARE_ZONE_API_TOKEN` for Cloudflare.

Variable | Description | Default
| - | - | -
`ACMESPIDER_HOSTNAME` | The hostname of the ACMESpider server | **Required** (no default)
`ACMESPIDER_ACME_TOS_ACCEPT` | Please set this to `true` to confirm you accept the TOS of the ACME provider (i.e. Let's Encrypt) | **Required** (no default)
`ACMESPIDER_ACME_EMAIL` | Your email address to register with the ACME provider (i.e. Let's Encrypt) | **Required** (no default)
`ACMESPIDER_ACME_CA_DIRECTORY` | URL of the ACME provider | `https://acme-v02.api.letsencrypt.org/directory`
`ACMESPIDER_PUBLIC_RESOLVERS` | Public DNS servers to use when internally checking the DNS-01 challenge (comma-separated) | `1.1.1.1,8.8.8.8`

## Client Configuration

Most ACME clients have a configuration option such as "ACME CA", "ACME Server", etc. to use a custom ACME server.

ACMESpider provides the directory endpoint at `/acme/directory`.

### Caddy

Use the global `acme_ca` directive:

```
{
    acme_ca https://acmespider.internal.example.com/acme/directory
}
```

### Certbot

Append the `--server` flag to your Certbot command:

```
certbot ... --server https://acmespider.internal.example.com/acme/directory
```

### acme.sh

Append the `--server` flag to your acme.sh command:

```
acme.sh --issue ... --server https://acmespider.internal.example.com/acme/directory
```

### Traefik

**YAML:**

```yaml
certificatesResolvers:
  acmespider:
    acme:
      caServer: https://acmespider.internal.example.com/acme/directory
```

**CLI:**

```
--certificatesresolvers.acmespider.acme.caserver=https://acmespider.internal.example.com/acme/directory
```