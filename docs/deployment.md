# Public deployment

PhishGuard is configured as a free Render Docker web service by the root-level
`render.yaml` Blueprint. The deployment uses the same digest-pinned, non-root
container that is exercised by CI and loads the four verified model artifacts
from the image.

## Create the service

1. Sign in to Render and open the Blueprint creation page.
2. Enter `https://github.com/ProtoTin/phishguard-ai` as the public repository.
3. Review the proposed `phishguard-ai-prototin` free web service and apply it.
4. Wait for the image build and the `/ready` health check to pass.
5. Open `https://phishguard-ai-prototin.onrender.com/` and run a benign test.

The repository can also be opened through the **Deploy to Render** button in the
README. No application secret, database, persistent disk, or raw training dataset
is required.

## Production configuration

| Setting | Value | Purpose |
| --- | --- | --- |
| Runtime | Docker | Reuses the reviewed production image |
| Plan | Free | Avoids an ongoing charge for the portfolio demo |
| Region | Oregon | Keeps the initial demo configuration explicit |
| Port | Render-assigned `PORT` | Keeps the container listener and health check synchronized |
| Health path | `/ready` | Confirms the API and verified artifacts are available |
| Environment | `production` | Enables production-only response protections |
| Allowed hosts | Public hostname plus local loopback | Rejects unexpected hosts while allowing container health probes |
| Auto-deploy | After checks pass | Prevents deployment before required GitHub checks succeed |

If the service name or public hostname is changed, update
`PHISHGUARD_ALLOWED_HOSTS` to the exact new hostname before deploying. Preserve
`localhost` and `127.0.0.1` for the container's internal health probe.
The container reads Render's assigned `PORT` at startup and defaults to `8000`
for local use; the Blueprint intentionally does not override this platform value.

## Verification

After each production deployment, verify these endpoints without submitting
private content:

```bash
curl --fail --show-error https://phishguard-ai-prototin.onrender.com/health
curl --fail --show-error https://phishguard-ai-prototin.onrender.com/ready
```

Then confirm that the dashboard loads, `youtube.com` is not classified as
phishing, an obviously deceptive test URL receives a warning, unexpected host
headers are rejected, and analysis responses include `Cache-Control: no-store`.

## Free-tier limitations

Render free web services spin down after a period without traffic, so the first
request after inactivity can take about a minute. The service filesystem is
ephemeral; PhishGuard does not rely on runtime persistence because its reviewed
configuration and model artifacts are built into the image.

The application rate limiter protects a single process. The free demo does not
claim distributed edge throttling or enterprise availability and must remain an
advisory portfolio system rather than an automated security control.
