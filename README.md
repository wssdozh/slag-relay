# slag-relay

Sync relay and Telegram bot for [SLAG](https://github.com/wssdozh/slag-v2). Python 3.12+,
standard library plus `cryptography`, SQLite for storage.

The relay moves encrypted bundles between devices, queues reminders, and passes assistant
questions to a device. Vault contents stay encrypted: the relay sees ciphertext and routing
metadata, not notes. Reminder titles and bodies are the exception and live in the notification
queue as plain text.

## Tests

```sh
python -m pytest -q
```

No network access or production credentials are needed. The suite starts a fake AI upstream and
uses temporary SQLite databases.

## Run locally

```sh
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python server.py --port 8320 --db data/relay.db
```

Without `SLAG_TG_BOT_TOKEN` the bot does not poll and notifications stay queued. Without
`KIE_API_KEY` and `GROQ_API_KEY` the AI gateway answers `503` instead of inventing an answer.

## Environment

| variable | default | what it does |
| --- | --- | --- |
| `SLAG_REQUIRE_ACCOUNT_AUTH` | `false` | require account auth; set `true` in production |
| `SLAG_TG_BOT_TOKEN` | — | Telegram bot token; absent means no polling and no delivery |
| `SLAG_NOTIFY_PEPPER` | — | scopes a route token to one vault; absent disables invites |
| `SLAG_ADMIN_TOKEN` | — | admin endpoints and the smoke probes |
| `SLAG_TRUSTED_PROXIES` | — | comma-separated proxy networks for client IPs |
| `KIE_API_KEY` | — | master key for the subscription AI gateway |
| `GROQ_API_KEY` | — | key for vision and Whisper endpoints |
| `SLAG_STATIC_DIR` | `./dist` | optional directory with the landing files |

`DEPLOYMENT.md` lists the rest: models, limits, TTLs, nginx and systemd.

## Layout

| path | role |
| --- | --- |
| `server.py` | composition root, auth, CLI, process start |
| `router.py` | dispatches HTTP requests to one `routes_*.py` domain |
| `routes_*.py` | one HTTP domain per file |
| `realtime.py` | websocket link for sync bundles and presence |
| `store/` | SQLite schema and stores |
| `bot.py`, `delivery.py` | Telegram polling and the notification queue |
| `assistant.py`, `assistant_actions.py` | questions from Telegram and their actions |
| `tg.py`, `premium.py` | Telegram formatting and premium emoji |
| `ai_proxy.py` | subscription AI gateway and media proxy |
| `test_*.py` | tests, including the architecture gate |

## Deploy

`DEPLOYMENT.md` covers systemd, nginx, backups and rollback. Ship the whole tree: `server.py`
imports its siblings, and a half-copied directory dies with `ModuleNotFoundError`.

## Secrets

CI runs tests only and needs no secrets. Deployment credentials belong on the server in a systemd
drop-in with mode `600`.

If a deploy workflow is added later, these repository secrets are the ones to set, one command per
name:

```sh
gh secret set -R wssdozh/slag-relay SLAG_TG_BOT_TOKEN
gh secret set -R wssdozh/slag-relay SLAG_NOTIFY_PEPPER
gh secret set -R wssdozh/slag-relay SLAG_ADMIN_TOKEN
gh secret set -R wssdozh/slag-relay KIE_API_KEY
gh secret set -R wssdozh/slag-relay GROQ_API_KEY
```

`gh` prompts for the value, so it never lands in shell history, git or a log.
