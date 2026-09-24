# OSINT Board — backend

Python 3.11+ package `osint_board`: FastAPI API, module framework, feed runner, arq worker and CLI.

```bash
uv sync --extra dev          # create .venv with dev tools
uv run pytest -q             # tests (no services needed)
uv run osint-board api       # http://localhost:8000/api/docs
uv run osint-board feeds --once usgs        # one poll of a feed, printed
uv run osint-board modules run crt_sh domain example.com
uv run osint-board search parse "mmsi:366999999 layer:maritime since:24h"
```

Layout is described in `../docs/01-architecture.md`; the module contract in `../docs/03-module-framework.md`.
