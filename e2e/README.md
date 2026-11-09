# End-to-end tests

Test various ACME clients against ACMESpider inside Docker.

```
e2e/run.sh all                 # start the stack, run every client, tear down (about 4 minutes)
e2e/run.sh up                  # just start it
e2e/run.sh test certbot caddy  # run some clients against a running stack
E2E_TARGET=pebble e2e/run.sh test   # run the same scenarios against the reference CA instead
e2e/run.sh down
```

All of it is containers on one private docker network:

| | |
|---|---|
| `pebble` | Let's Encrypt's test CA. It plays the "real" CA that ACMESpider gets certificates from. |
| `dnsmock` | A small authoritative DNS server for the `.test` zone (`e2e/dnsmock`). ACMESpider publishes DNS-01 TXT records here and Pebble validates against it. |
| `acmespider` | The thing under test, built from this checkout, running with TLS as in the README: at startup it gets *its own* certificate from Pebble over DNS-01. |
| clients | certbot, lego v5, lego v4, caddy, acme.sh and traefik, from their official images. Each gets a network alias like `certbot.test`, so ACMESpider's HTTP-01 fetch of `http://certbot.test/.well-known/...` lands on the client. |

Issued certificates are checked independently on the host: the SANs must be exactly the requested names, and the
chain must verify against Pebble's root.

## Known gaps, and the reference

`known_gap` checks cover features ACMESpider doesn't implement yet (revocation, key rollover, looking an account up by
key). They are reported but don't fail the run; if one starts passing it says `NOW PASSES` so it can be promoted to a
normal check.

A check like that is only meaningful if the command line is right, so `E2E_TARGET=pebble` runs every scenario
against Pebble, which implements all of it. Every check, `known_gap` ones included, must pass there.

## Notes

- Modern clients refuse a plain-HTTP ACME directory, which is why ACMESpider runs with TLS here.
- HTTP-01 must be on port 80: ACMESpider fetches `http://<domain>/...` with no port. The pebble reference uses 5002.
- Client state lives in named docker volumes rather than bind mounts, which are racy on some docker VMs.
- The images are a few hundred MB in total. `docker image rm` the ones you don't want afterwards.
