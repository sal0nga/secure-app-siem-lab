.PHONY: help up down logs scan zap seed attack evidence

## Show this help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS := ":.*?## "}; {printf "\033[36m%-12s\033[0m %s\n", $$1, $$2}'

up:            ## bring up stack in dev (wired in later phases)
	@echo "Phase 0: no services yet. Will start containers in Phase 1."

down:          ## stop and remove containers
	@echo "Phase 0: nothing to stop."

logs:          ## follow app logs
	@echo "Phase 0: no logs yet."

scan:          ## run Semgrep/Trivy
	@echo "Phase 0: scanners wired later."

zap:           ## run ZAP baseline
	@echo "Phase 0: ZAP integration comes later."

seed:          ## seed Keycloak and DB
	@echo "Phase 0: seeding added in IAM phase."

attack:        ## run synthetic attacks
	@echo "Phase 0: attack sims added with SIEM."

evidence:      ## export screenshots/pcaps
	@echo "Phase 0: ensure evidence/ exists; add artifacts as you go."
