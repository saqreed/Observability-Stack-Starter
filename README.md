# Observability Stack (Metrics + Logs + Alerts + SLOs)

Self-contained observability stack using Docker Compose: Prometheus, Alertmanager, Grafana, Elasticsearch, Kibana, Filebeat, Blackbox Exporter and a demo Go service (`hello-api`) with SLI/SLO rules and burn-rate alerts. One-command bootstrap with `.env`.

## Repository

- GitHub: <https://github.com/saqreed/Observability-Stack-Starter>
- Clone:

```bash
git clone https://github.com/saqreed/Observability-Stack-Starter.git
cd Observability-Stack-Starter
```

## Prerequisites

- Docker Desktop (or Docker Engine + Compose v2)
- Windows PowerShell (for the provided Makefile helpers on Windows) or GNU Make (optional)

## Features

- Prometheus with service/infrastructure rules and SLO burn-rate alerts
- Demo Go service `hello-api` exposing Prometheus metrics (`http_requests_total`, `http_request_duration_seconds_bucket`)
- Blackbox synthetic checks (HTTP and ICMP)
- Grafana provisioning (Prometheus + Elasticsearch datasources, placeholder dashboards)
- Elasticsearch + ILM + Filebeat (ingests logs from a shared log volume)
- Alertmanager routing (warning/critical) with email receiver (Telegram relay can be added)

## Quickstart

1. Copy environment and optionally adjust:

```powershell
copy .env.example .env
```

1. Build and start:

```bash
docker compose build hello-api
docker compose up -d
```

1. Bootstrap Elasticsearch ILM and index template (first run):

```powershell
powershell -NoProfile -Command "\
$ErrorActionPreference='Stop'; \
Invoke-RestMethod -Method Put -Uri 'http://localhost:9200/_ilm/policy/logs-ilm' -ContentType 'application/json' -InFile 'elasticsearch/ilm/policy-logs.json'; \
Invoke-RestMethod -Method Put -Uri 'http://localhost:9200/_index_template/logs-template' -ContentType 'application/json' -InFile 'elasticsearch/ilm/template-logs.json' \
"
```

1. Open UIs:

- Prometheus: <http://localhost:9090>
- Alertmanager: <http://localhost:9093>
- Grafana: <http://localhost:3000> (default admin/admin123)
- Elasticsearch: <http://localhost:9200>
- Kibana: <http://localhost:5601>
- Blackbox: <http://localhost:9115>

## Services

- `services/hello-api` Go demo service on `:8080` with endpoints:
  - `/` – hello
  - `/sleep?ms=250` – latency generator
  - `/error` – 50% 500 responses
  - `/metrics` – Prometheus metrics

Prometheus scrapes `hello-api:8080` and records:

- Availability ratio from `http_requests_total` with `code` label
- Latency p95 via `histogram_quantile` over `http_request_duration_seconds_bucket`

## Logs

- A lightweight `logger` container writes into a shared `logs_data` volume
- Filebeat reads `/shared-logs/*.log` and sends to Elasticsearch index pattern `logs-*`
- ILM policy rolls over and deletes old indices (see `elasticsearch/ilm/`)

## Alerting & SLOs

- Fast-burn (5m/1h) and slow-burn (30m/6h) alerts for 99.5% availability (hello-api)
- p95 latency alert (>250ms)
- Infrastructure alert examples (Node exporter down, Elasticsearch red)
- Alertmanager routes `warning` to email (`ALERT_EMAIL_TO`) and `critical` to `pager` (placeholder)

## Project Tree

```text
observability-stack/
  README.md
  .env.example
  docker-compose.yml
  Makefile
  docs/
    RUNBOOK.md
  grafana/
    provisioning/
      datasources/datasource.yaml
      dashboards/
        dashboards.yaml
        nodes.json
        services.json
        blackbox.json
  prometheus/
    prometheus.yml
    alerting/
      rules-services.yml
      rules-infra.yml
      rules-slo.yml
    blackbox/
      blackbox.yml
  alertmanager/
    alertmanager.yml
  elasticsearch/
    ilm/
      policy-logs.json
      template-logs.json
  filebeat/
    filebeat.yml
  services/
    hello-api/
      Dockerfile
      go.mod
      main.go
```

## Make targets (optional)

- `make up` – start services and bootstrap ILM
- `make down` – stop services
- `make clean` – remove volumes and data (destructive)
- `make status` – check endpoints
- `make smoke` – quick health checks

## Troubleshooting

- Build the Go service explicitly on first run: `docker compose build hello-api`
- Check container logs: `docker compose logs -f <service>`
- Prometheus targets: <http://localhost:9090/targets>
- Alertmanager status: <http://localhost:9093/#/status>
- ES health: `GET <http://localhost:9200/_cluster/health>`

## Notes

- Tune Elasticsearch heap: `ES_JAVA_OPTS` in `docker-compose.yml`
- For production, secure ports and use TLS/reverse proxy
- You can replace the demo service with your app as long as it exposes the same metrics/labels

## Architecture

```text
Apps (hello-api) ----> Prometheus ----> Grafana
          |                |  \
          |                |   \--> Alertmanager --> Email/Webhook
          |                |
          |                +--> Blackbox Exporter (HTTP/ICMP)
          |
Logger ---> Filebeat ----> Elasticsearch ----> Kibana
```

Ports (default):

- Prometheus 9090, Alertmanager 9093, Grafana 3000, Elasticsearch 9200, Kibana 5601, Blackbox 9115, node_exporter 9100, hello-api 8080

## Configuration

Environment variables (`.env`):

```env
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=admin123
TELEGRAM_BOT_TOKEN=xxxx
TELEGRAM_CHAT_ID=123456
ALERT_EMAIL_TO=you@example.com
```

Adjust heap and resources in `docker-compose.yml` (e.g. `ES_JAVA_OPTS`).

## SLI/SLO Details

- Availability SLI is computed from `http_requests_total` using label `code` to filter non-5xx as good events.
- Example SLO target: 99.5% for `hello-api` with multi-window burn-rate alerts:
  - Fast burn: 5m and 1h windows > 14.4x budget
  - Slow burn: 30m and 6h windows > 6x budget
- Latency SLI: p95 via `histogram_quantile` over `http_request_duration_seconds_bucket` (threshold 250ms by default).

Rules: see `prometheus/alerting/rules-slo.yml` and `prometheus/alerting/rules-services.yml`.

## Alert Routing

- Routing is defined in `alertmanager/alertmanager.yml`.
- Default receivers:
  - `default`/`chat`: email to `ALERT_EMAIL_TO`
  - `pager`: placeholder webhook (suitable for a small Telegram relay or another on-call channel)
- Tuning intervals: `group_wait`, `group_interval`, `repeat_interval`.

## Resource Requirements

- Minimum for demo: 4 vCPU, 8–12 GB RAM, 50+ GB SSD (Elasticsearch is storage-heavy).
- If constrained, lower ES heap and reduce retention; disable services you do not need.

## FAQ

- Q: I do not see logs in Kibana.
  - A: Ensure ILM/template bootstrap ran successfully and `logger` + `filebeat` containers are running.
- Q: Prometheus shows `hello-api` down.
  - A: Build the service first: `docker compose build hello-api`, then `docker compose up -d`.
- Q: Telegram alerts?
  - A: Use a small relay/webhook that transforms Alertmanager payload to Telegram API format, or switch to email/Slack.

## License

MIT License. See `LICENSE` file if provided.
