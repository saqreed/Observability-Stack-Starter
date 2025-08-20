# 1) Название и цель

**Observability Stack (Metrics + Logs + Alerts + SLOs)**
Цель — за 1 команду поднять стек наблюдаемости: **Prometheus** (метрики), **Alertmanager** (оповещения), **ELK (Elasticsearch + Kibana + Filebeat/Logstash)** для логов, **Grafana** для метрик-дашбордов, **Blackbox Exporter** для синтетических проверок, **готовые SLO** для pet-сервисов и синтетики с burn-rate алертами.

# 2) Область работ (Scope)

Включено:

* Развёртывание инфраструктуры наблюдаемости в Docker Compose (по умолчанию), профиль Helm для k8s (опция).
* Метрики: Prometheus, node\_exporter, blackbox\_exporter, exporters для сервисов (опционально: cadvisor, postgres\_exporter и т.п.).
* Логи: Filebeat → Elasticsearch (опц. Logstash для парсинга), Kibana с преднастроенными индексами и ILM.
* Дашборды: Grafana (метрики) + Kibana (логи), импорт базовых дашбордов.
* SLI/SLO: для 2 примерных сервисов (`hello-api`, `notes-web`) и для синтетики (HTTP/ICMP/TCP).
* Alerting: многоканальная маршрутизация (Telegram/Email/Webhook), multi-window/multi-burn-rate правила.
* One-command bootstrap, Makefile, .env, готовые правила ретенции/ротации.

Вне scope (MVP):

* Tracing (Jaeger/Tempo), full OTEL-pipeline (можно в roadmap).
* Продвинутые корреляции метрик/логов/трейсов (flow maps).
* Долгосрочная долговременная метрика-хранилка (Thanos/Cortex).

# 3) Архитектура и поток данных

**Метрики:** target’ы (node\_exporter/экспортеры/blackbox) → Prometheus → Grafana → Alertmanager (оповещения).
**Логи:** приложения/системы → Filebeat (на хосте) → Elasticsearch (индексы по шаблонам и ILM) → Kibana.
**Синтетика:** blackbox\_exporter (HTTP/ICMP/TCP/TLS-expiry) с scrape из Prometheus → SLO/алерты.

Порты (дефолт):

* Prometheus 9090, Alertmanager 9093, Grafana 3000, Elasticsearch 9200, Kibana 5601, Blackbox 9115, node\_exporter 9100.

# 4) Нефункциональные требования

* Идемпотентность: повторный запуск не ломает состояние.
* Низкий порог входа: один `.env` + `make up`.
* Ресурсы (минимум): 4 vCPU, 8–12 GB RAM, 50+ GB SSD (под ES) — для демо-нагрузки.
* Безопасность: пароли/токены — в `.env`/Docker secrets; доступ с локальной сети, reverse-proxy/TLS — опционально.
* Документация и runbook в `docs/`.

# 5) Структура репозитория

```
observability-stack/
  README.md
  .env.example
  docker-compose.yml
  Makefile
  docs/
    RUNBOOK.md
    SLOs.md
    Dashboards.md
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
    templates/telegram.tmpl
  elasticsearch/
    es01/
      Dockerfile (опц.)
    ilm/
      policy-logs.json
      template-logs.json
  filebeat/
    filebeat.yml
  logstash/ (опц.)
    pipeline.conf
  k8s/ (опц. helm values + manifests)
    values-prometheus.yaml
    values-alertmanager.yaml
    values-efk.yaml
```

# 6) Bootstrap и команды

`make up` — запуск стека (создание volume, старт сервисов), импорт дашбордов/датасорсов.
`make down` — остановка.
`make clean` — полная очистка volumes/индексов (необратимо).
`make status` — проверка доступности HTTP-эндпоинтов.
`make smoke` — проверка метрик/логов + тестовые алерты.

Пример `Makefile` (выдержка):

```Makefile
SHELL := /bin/bash
ENV ?= .env

up:
	@export $$(cat $(ENV) | xargs) && docker compose up -d --remove-orphans
	@sleep 8 && make grafana-provision es-provision

down:
	@docker compose down

clean:
	@docker compose down -v

status:
	@curl -sf http://localhost:9090/-/ready && echo "Prometheus OK"
	@curl -sf http://localhost:3000/api/health && echo "Grafana OK" || true
	@curl -sf http://localhost:9200 && echo "Elasticsearch OK" || true
	@curl -sf http://localhost:5601/api/status && echo "Kibana OK" || true

grafana-provision:
	@echo "Grafana datasources/dashboards provisioned (auto on start)"

es-provision:
	@curl -s -XPUT "http://localhost:9200/_ilm/policy/logs-ilm" \
	 -H 'Content-Type: application/json' --data-binary @elasticsearch/ilm/policy-logs.json
	@curl -s -XPUT "http://localhost:9200/_index_template/logs-template" \
	 -H 'Content-Type: application/json' --data-binary @elasticsearch/ilm/template-logs.json
```

# 7) Конфиги: Docker Compose (ядро)

```yaml
version: "3.9"
services:
  prometheus:
    image: prom/prometheus:v2.53.0
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./prometheus/alerting:/etc/prometheus/alerting:ro
      - prom_data:/prometheus
    command: ["--config.file=/etc/prometheus/prometheus.yml","--storage.tsdb.retention.time=30d"]
    ports: ["9090:9090"]
    depends_on: [blackbox, nodeexporter]

  alertmanager:
    image: prom/alertmanager:v0.27.0
    volumes:
      - ./alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro
      - alert_data:/alertmanager
      - ./alertmanager/templates:/etc/alertmanager/templates:ro
    ports: ["9093:9093"]

  blackbox:
    image: prom/blackbox-exporter:v0.25.0
    volumes:
      - ./prometheus/blackbox/blackbox.yml:/etc/blackbox_exporter/config.yml:ro
    ports: ["9115:9115"]

  nodeexporter:
    image: prom/node-exporter:v1.8.1
    pid: host
    network_mode: host
    command: ["--path.rootfs=/host"]
    volumes:
      - /:/host:ro,rslave

  grafana:
    image: grafana/grafana:11.0.0
    environment:
      - GF_SECURITY_ADMIN_USER=${GRAFANA_ADMIN_USER}
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}
    volumes:
      - ./grafana/provisioning:/etc/grafana/provisioning
      - graf_data:/var/lib/grafana
    ports: ["3000:3000"]
    depends_on: [prometheus]

  elasticsearch:
    image: elasticsearch:8.13.4
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms2g -Xmx2g
    volumes:
      - es_data:/usr/share/elasticsearch/data
    ports: ["9200:9200"]

  kibana:
    image: kibana:8.13.4
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports: ["5601:5601"]
    depends_on: [elasticsearch]

  filebeat:
    image: elastic/filebeat:8.13.4
    user: root
    volumes:
      - ./filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /var/log:/var/log:ro
    depends_on: [elasticsearch]
    command: ["--strict.perms=false"]

volumes:
  prom_data:
  alert_data:
  graf_data:
  es_data:
```

`.env.example`:

```
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=admin123
TELEGRAM_BOT_TOKEN=xxxx
TELEGRAM_CHAT_ID=123456
ALERT_EMAIL_TO=you@example.com
```

# 8) Prometheus: targets + blackbox

`prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 30s

rule_files:
  - "alerting/*.yml"

scrape_configs:
  - job_name: "prometheus"
    static_configs: [{ targets: ["prometheus:9090"] }]

  - job_name: "node"
    static_configs: [{ targets: ["localhost:9100"] }]

  - job_name: "hello-api"
    metrics_path: /metrics
    static_configs:
      - targets: ["host.docker.internal:8081"]  # пример
        labels: { service: "hello-api" }

  - job_name: "notes-web"
    metrics_path: /metrics
    static_configs:
      - targets: ["host.docker.internal:8082"]
        labels: { service: "notes-web" }

  - job_name: "blackbox-http"
    metrics_path: /probe
    params:
      module: [http_2xx, http_tls, http_latency]
    static_configs:
      - targets:
          - https://example.com/health
          - http://host.docker.internal:8081/health
        labels: { probe: "http" }
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - target_label: __address__
        replacement: blackbox:9115
      - source_labels: [__param_target]
        target_label: instance

  - job_name: "blackbox-icmp"
    metrics_path: /probe
    params: { module: [icmp] }
    static_configs:
      - targets: ["8.8.8.8", "1.1.1.1"]
        labels: { probe: "ping" }
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - target_label: __address__
        replacement: blackbox:9115
      - source_labels: [__param_target]
        target_label: instance
```

`prometheus/blackbox/blackbox.yml`:

```yaml
modules:
  http_2xx:
    prober: http
    http:
      preferred_ip_protocol: "ip4"
      valid_http_versions: ["HTTP/1.1", "HTTP/2"]
      fail_if_not_ssl: false

  http_tls:
    prober: http
    http:
      tls_config:
        insecure_skip_verify: false
      fail_if_not_ssl: true
      valid_http_versions: ["HTTP/2","HTTP/1.1"]

  http_latency:
    prober: http
    http:
      method: GET
      no_follow_redirects: false

  tcp_connect:
    prober: tcp

  icmp:
    prober: icmp
    icmp:
      preferred_ip_protocol: "ip4"
```

# 9) Alertmanager: маршрутизация

`alertmanager/alertmanager.yml`:

```yaml
global:
  resolve_timeout: 5m

route:
  receiver: "default"
  group_by: ["alertname","service"]
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 3h
  routes:
    - matchers: [ severity="critical" ]
      receiver: "pager"
      repeat_interval: 1h
    - matchers: [ severity="warning" ]
      receiver: "chat"

receivers:
  - name: "default"
    email_configs:
      - to: ${ALERT_EMAIL_TO}

  - name: "pager"
    webhook_configs:
      - url: "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage"
        http_config:
          bearer_token_file: /dev/null
        send_resolved: true
        # Используем шаблон, который формирует payload для Telegram через webhook proxy или
        # через alertmanager-webhook-telegram (если добавишь)

  - name: "chat"
    email_configs:
      - to: ${ALERT_EMAIL_TO}

templates:
  - "/etc/alertmanager/templates/telegram.tmpl"
```

> Примечание: для Telegram удобно использовать готовый webhook-relay/бот-адаптер; в README указать два варианта (прямой через bot API через webhook-реле или сторонний image).

# 10) Логирование: Filebeat → Elasticsearch

`filebeat/filebeat.yml` (минимум):

```yaml
filebeat.inputs:
  - type: filestream
    id: system-logs
    enabled: true
    paths:
      - /var/log/*.log
      - /var/log/syslog
      - /var/log/auth.log

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "logs-%{+yyyy.MM.dd}"

setup.ilm.enabled: true
setup.ilm.policy_name: "logs-ilm"
setup.template.name: "logs-template"
setup.template.pattern: "logs-*"
```

ILM политика/шаблон:
`elasticsearch/ilm/policy-logs.json`:

```json
{
  "policy": {
    "phases": {
      "hot": { "actions": { "rollover": { "max_age": "7d", "max_size": "25gb" } } },
      "warm": { "min_age": "7d", "actions": { "forcemerge": { "max_num_segments": 1 } } },
      "delete": { "min_age": "30d", "actions": { "delete": {} } }
    }
  }
}
```

`elasticsearch/ilm/template-logs.json`:

```json
{
  "index_templates": [{
    "name": "logs-template",
    "index_template": {
      "index_patterns": ["logs-*"],
      "template": {
        "settings": {
          "index.lifecycle.name": "logs-ilm",
          "index.lifecycle.rollover_alias": "logs"
        }
      },
      "data_stream": {}
    }
  }]
}
```

# 11) Grafana: provisioning

`grafana/provisioning/datasources/datasource.yaml`:

```yaml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
  - name: Elasticsearch-Logs
    type: elasticsearch
    access: proxy
    url: http://elasticsearch:9200
    jsonData:
      timeField: "@timestamp"
      esVersion: "8.0+"
```

`grafana/provisioning/dashboards/dashboards.yaml` — указывает на JSON-дашборды (`nodes.json`, `services.json`, `blackbox.json`).
Содержание:

* **Nodes**: CPU/RAM/Disk/Load, fs saturation, network.
* **Services**: RPS, error rate, p95/p99 latency (из histogram bucket’ов), availability SLI, SLO burn.
* **Blackbox**: probe\_success, TLS expiry (через `probe_ssl_earliest_cert_expiry`), RTT, HTTP статус/редиректы.

# 12) SLI/SLO: определения и правила

**Сервисы:**

* **Доступность (Availability SLI)**: доля успешных запросов (HTTP 2xx/3xx, без 5xx).
* **Задержка (Latency SLI)**: процент запросов быстрее выбранного порога (например, p95 < 250ms).

**Синтетика:**

* **Uptime SLI**: `avg_over_time(probe_success[window])`.
* **TLS SLI**: время до истечения сертификата > N дней.

**Targets (пример для месяца=30d):**

* hello-api: `Availability SLO = 99.5%`, `Latency (p95) < 250ms для 99% запросов`.
* notes-web: `Availability SLO = 99.0%`, `Latency (p95) < 300ms`.

**Error budget**:

* 99.5% → бюджет 0.005 (0.5% ошибок).
* Burn-rate алерты multi-window:

  * Page: 5m & 1h окна, порог 14.4× бюджета.
  * Ticket: 30m & 6h окна, порог 6× бюджета.

`prometheus/alerting/rules-slo.yml` (выдержка; адаптируй метрики под свои имена):

```yaml
groups:
- name: slo-services
  interval: 30s
  rules:
  # --- Availability ratio (good/total) ---
  - record: service:request_total:rate5m
    expr: sum by(service) (rate(http_requests_total[5m]))
  - record: service:request_good:rate5m
    expr: sum by(service) (rate(http_requests_total{code!~"5.."}[5m]))
  - record: service:availability:ratio5m
    expr: service:request_good:rate5m / service:request_total:rate5m

  - record: service:request_total:rate1h
    expr: sum by(service) (rate(http_requests_total[1h]))
  - record: service:request_good:rate1h
    expr: sum by(service) (rate(http_requests_total{code!~"5.."}[1h]))
  - record: service:availability:ratio1h
    expr: service:request_good:rate1h / service:request_total:rate1h

  # --- Burn rate vs target (example hello-api 99.5%) ---
  - record: slo:availability:burnrate5m
    expr: (1 - service:availability:ratio5m{service="hello-api"}) / 0.005
  - record: slo:availability:burnrate1h
    expr: (1 - service:availability:ratio1h{service="hello-api"}) / 0.005
  - alert: SLOAvailabilityFastBurn_HelloAPI
    expr: slo:availability:burnrate5m > 14.4 and slo:availability:burnrate1h > 14.4
    for: 5m
    labels: { severity: "critical", service: "hello-api" }
    annotations:
      summary: "SLO burn rate FAST (hello-api)"
      description: "Error budget burning too fast (5m & 1h > 14.4)."

  - record: slo:availability:burnrate30m
    expr: (1 - (sum by(service) (rate(http_requests_total{service="hello-api",code!~"5.."}[30m])) / sum by(service) (rate(http_requests_total{service="hello-api"}[30m])))) / 0.005
  - record: slo:availability:burnrate6h
    expr: (1 - (sum by(service) (rate(http_requests_total{service="hello-api",code!~"5.."}[6h])) / sum by(service) (rate(http_requests_total{service="hello-api"}[6h])))) / 0.005
  - alert: SLOAvailabilitySlowBurn_HelloAPI
    expr: slo:availability:burnrate30m > 6 and slo:availability:burnrate6h > 6
    for: 30m
    labels: { severity: "warning", service: "hello-api" }
    annotations:
      summary: "SLO burn rate SLOW (hello-api)"
      description: "Budget burns above 6x on 30m & 6h."
```

**Latency (p95)**:

```yaml
  - record: service:latency_ms:p95_5m
    expr: 1000 * histogram_quantile(0.95, sum by (service, le) (rate(http_request_duration_seconds_bucket[5m])))
  - alert: LatencyP95TooHigh_HelloAPI
    expr: service:latency_ms:p95_5m{service="hello-api"} > 250
    for: 10m
    labels: { severity: "warning" }
    annotations:
      summary: "p95 latency > 250ms (hello-api)"
```

**SLO для синтетики (HTTP/ICMP)**:

```yaml
- name: slo-synthetic
  rules:
  - record: probe:availability:ratio5m
    expr: avg by(instance) (avg_over_time(probe_success[5m]))
  - record: slo:probe:burnrate5m
    expr: (1 - probe:availability:ratio5m) / 0.005  # SLO 99.5%
  - record: tls:expiry_seconds
    expr: probe_ssl_earliest_cert_expiry - time()
  - alert: TLScertExpiresSoon
    expr: tls:expiry_seconds < 86400 * 7
    for: 5m
    labels: { severity: "warning" }
    annotations:
      summary: "TLS сертификат истекает < 7 дней"
```

# 13) Инфраструктурные алерты

`prometheus/alerting/rules-infra.yml` (сокр.):

```yaml
groups:
- name: infra
  rules:
  - alert: InstanceDown
    expr: up == 0
    for: 2m
    labels: { severity: "critical" }
    annotations: { description: "Target {{ $labels.instance }} down" }

  - alert: NodeHighCPU
    expr: avg by(instance) (rate(node_cpu_seconds_total{mode!="idle"}[5m])) > 0.85
    for: 10m
    labels: { severity: "warning" }

  - alert: NodeLowDisk
    expr: (node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes{fstype!~"tmpfs|overlay"}) < 0.1
    for: 10m
    labels: { severity: "warning" }

  - alert: ElasticsearchRed
    expr: elasticsearch_cluster_health_status{color="red"} == 1
    for: 2m
    labels: { severity: "critical" }
```

# 14) Дашборды (минимальный набор)

* **Nodes**: CPU idle/busy, Load, RAM, FS usage/inodes, Net in/out, IO saturation.
* **Services**: RPS, err rate (5xx), p95/p99, SLI Availability, SLO burn, top endpoints.
* **Synthetic**: probe\_success, RTT, HTTP code, TLS expiry.
* **Logs (Kibana)**: системные события, Nginx/приложение (поля: ts, level, message, trace\_id (если есть)).

# 15) Безопасность и доступ

* Ограничить публикацию портов наружу, использовать `localhost` бинды или reverse-proxy с HTTP Basic / OAuth proxy.
* Пароли/токены в `.env`/Docker secrets.
* (Опц.) mTLS/HTTPS через Traefik/nginx-proxy.

# 16) Acceptance Criteria

1. `make up` поднимает все сервисы, страницы здоровья зелёные.
2. Grafana показывает дашборды, Prometheus видит target’ы, Kibana видит индекс `logs-*`.
3. Синтетические HTTP-пробы работают, есть dashes/графики, TLS-expiry алерт срабатывает на тестовом домене.
4. Для `hello-api` корректно считаются SLI/SLO и работают **обе** burn-rate сигналки.
5. Алерты доставляются в указанный канал (Email/Telegram), маршрутизация по severity.
6. ILM рулит ротацией логов (rollover hot → warm → delete).

# 17) Тест-план

* **Smoke:** `make smoke` → curl на `/metrics`, проверка `up` метрик, доступности Grafana/Kibana.
* **SLO-burn:** искусственно генерировать 5xx (скрипт бомбардировки) → поймать fast & slow burn алерты.
* **Latency:** добавить sleep в эндпоинт → p95 > порога → алерт.
* **Synthetic:** выключить сервис/порт → `probe_success=0` → алерт.
* **Logs:** сгенерировать тестовые записи → индекс появился, поиск в Kibana.
* **ILM:** принудительный rollover (API) → проверить новые индексы.

# 18) K8s вариант (опционально)

* Prometheus/Alertmanager/Grafana/EFK через Helm (values в `k8s/`).
* Prometheus Operator (opц.) — CRD Rule/Alert/ServiceMonitor; либо vanilla Helm чарты.
* Filebeat/Fluent Bit как DaemonSet; ES/Kibana как StatefulSet/Deployment.
* Access — Ingress (traefik/nginx), cert-manager.

# 19) Риски и допущения

* ES прожорлив: на слабых хостах увеличивать swap нельзя, лучше поднять RAM/уменьшить heap.
* Метрики приложений должны иметь **стабильные** названия/лейблы (http\_requests\_total, http\_request\_duration\_seconds\_bucket и т.п.) — иначе адаптируй PromQL.
* Telegram требует корректный бот-токен/чат-ID или мост-вебхук.

# 20) Roadmap (дальше по красоте)

* **Loki** вместо/в дополнение к ELK для дешёвых логов.
* **OpenTelemetry Collector** для унификации метрик/логов/трейсов.
* **Tempo/Jaeger** для трассировок, корреляция trace\_id в логах/дашах.
* **SLO-генераторы**: Sloth (генерит rules/alerts из SLO YAML).
* **Alert dedup/silence UI**, Anomaly detection (Prometheus Adaptive Alerts, ES ML).
* **Synthetic++**: k6 + k6-operator для RUM/синтетики с профилями нагрузки.

