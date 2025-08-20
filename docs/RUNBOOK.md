# Runbook

## Startup

 
- Copy `.env.example` to `.env` and set secrets.
- `make up`
- `make status`

 

## Access

 
- Prometheus: <http://localhost:9090>
- Alertmanager: <http://localhost:9093>
- Grafana: <http://localhost:3000>
- Elasticsearch: <http://localhost:9200>
- Kibana: <http://localhost:5601>
- Blackbox: <http://localhost:9115>

 

## Common Operations

 
- Restart stack: `make down && make up`
- Bootstrap ILM/templates: `make bootstrap`
- Clean all data: `make clean` (destructive)

 

## Troubleshooting

 
- Check container logs: `docker compose logs -f <service>`
- Prometheus targets page: <http://localhost:9090/targets>
- Alertmanager status: <http://localhost:9093/#/status>
- ES health: `GET <http://localhost:9200/_cluster/health>`

 

## Oncall

 
- Alertroute by severity (critical->pager, warning->chat)
- Silence via Alertmanager UI
