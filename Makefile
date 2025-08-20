.PHONY: up down clean status bootstrap smoke

COMPOSE=docker compose

up:
	$(COMPOSE) up -d
	@$(MAKE) bootstrap

bootstrap:
	@echo "Provisioning Elasticsearch ILM and templates..."
	@powershell -NoProfile -Command \
	"\
	$ErrorActionPreference='Stop'; \
	Invoke-RestMethod -Method Put -Uri 'http://localhost:9200/_ilm/policy/logs-ilm' -ContentType 'application/json' -InFile 'elasticsearch/ilm/policy-logs.json'; \
	Invoke-RestMethod -Method Put -Uri 'http://localhost:9200/_index_template/logs-template' -ContentType 'application/json' -InFile 'elasticsearch/ilm/template-logs.json' \
	" || true

status:
	@echo "Checking endpoints..."
	@powershell -NoProfile -Command \
	"\
	$urls=@('http://localhost:9090','http://localhost:9093','http://localhost:3000','http://localhost:9200','http://localhost:5601','http://localhost:9115'); \
	foreach($u in $urls){ try { $r=Invoke-WebRequest -UseBasicParsing -Uri $u -TimeoutSec 3; Write-Host '[OK]' $u $r.StatusCode } catch { Write-Host '[DOWN]' $u } } \
	"

down:
	$(COMPOSE) down

clean:
	$(COMPOSE) down -v
	@echo "Volumes removed"

smoke:
	@powershell -NoProfile -Command \
	"\
	$metrics=@('http://localhost:9090/-/healthy','http://localhost:9093/#/status','http://localhost:3000/login'); \
	foreach($m in $metrics){ try { $r=Invoke-WebRequest -UseBasicParsing -Uri $m -TimeoutSec 3; Write-Host '[OK]' $m } catch { Write-Host '[FAIL]' $m } } \
	"
