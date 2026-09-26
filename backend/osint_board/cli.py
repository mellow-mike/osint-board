"""`osint-board` command line."""

from __future__ import annotations

import asyncio
import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from osint_board import __version__
from osint_board.config import get_settings
from osint_board.logging import configure_logging

app = typer.Typer(help="OSINT Board backend", no_args_is_help=True)
catalog_app = typer.Typer(help="Catalog commands")
modules_app = typer.Typer(help="Module commands")
search_app = typer.Typer(help="Search commands")
soak_app = typer.Typer(help="24-hour feed soak (scripts/soak.sh keeps it running unattended)", no_args_is_help=True)
app.add_typer(catalog_app, name="catalog")
app.add_typer(modules_app, name="modules")
app.add_typer(search_app, name="search")
app.add_typer(soak_app, name="soak")


@app.callback()
def _root() -> None:
    configure_logging()


@app.command()
def version() -> None:
    typer.echo(__version__)


@app.command()
def api(reload: bool = False, host: str | None = None, port: int | None = None) -> None:
    """Run the HTTP API (uvicorn)."""
    import uvicorn

    s = get_settings()
    uvicorn.run(
        "osint_board.api.app:app", host=host or s.api_host, port=port or s.api_port, reload=reload, factory=False
    )


@app.command()
def worker(queue: Annotated[str, typer.Option(help="default | tools")] = "default") -> None:
    """Run an arq worker for on-demand module runs."""
    from arq import run_worker

    from osint_board.worker.tasks import worker_settings

    run_worker(worker_settings(queue))  # type: ignore[arg-type]


@app.command()
def feeds(
    only: Annotated[list[str] | None, typer.Option(help="module ids to run")] = None, once: str | None = None
) -> None:
    """Run feed modules on their cadence (or one poll with --once <module_id>)."""
    from osint_board.feeds.runner import FeedRunner, MemorySink
    from osint_board.modules.registry import get_registry

    async def _main() -> None:
        registry = get_registry()
        if once:
            sink = MemorySink()
            n = await FeedRunner(registry, sink).run_once(once)
            typer.echo(f"{once}: {n} emissions")
            for _mid, e in sink.items[:10]:
                typer.echo(
                    json.dumps(
                        {
                            "type": e.type.value,
                            "value": e.value,
                            "key": e.key,
                            "geo": {
                                "lat": e.geo.lat,
                                "lon": e.geo.lon,
                                "alt_m": e.geo.alt_m,
                                "precision": e.geo.precision,
                            }
                            if e.geo
                            else None,
                        },
                        default=str,
                    )
                )
            return
        from osint_board.api.state import build_state
        from osint_board.feeds.db_sink import DbSink
        from osint_board.feeds.state import DbStateStore

        state = await build_state()
        # redis_url lets the sink reconnect when Redis was down at startup (otherwise live deltas stay off)
        sink = DbSink(state.redis, redis_url=state.settings.redis_url)
        try:
            await FeedRunner(registry, sink, only=set(only) if only else None, state_store=DbStateStore()).run_forever()
        finally:
            await sink.aclose()

    asyncio.run(_main())


class SoakSink(StrEnum):
    db = "db"
    null = "null"


@soak_app.command("run")
def soak_run(
    hours: Annotated[float, typer.Option(help="how long to run (a resumed run keeps its original deadline)")] = 24.0,
    out: Annotated[
        Path | None,
        typer.Option(help="run directory (default <repo>/data/soak/<UTC timestamp>); an unfinished run is resumed"),
    ] = None,
    only: Annotated[list[str] | None, typer.Option(help="module ids to run (repeatable; default every feed)")] = None,
    sink: Annotated[
        SoakSink, typer.Option(help="db: Postgres + Redis like `feeds`; null: check and count emissions only")
    ] = SoakSink.db,
    report_every: Annotated[float, typer.Option(min=1.0, help="seconds between IN PROGRESS report rewrites")] = 300.0,
    sample_every: Annotated[float, typer.Option(min=1.0, help="seconds between process samples")] = 60.0,
    state_file: Annotated[
        Path | None,
        typer.Option(help="each feed's last successful poll (default <out>/../feed_state.json, shared across runs)"),
    ] = None,
) -> None:
    """Run the feeds for --hours, journaling every event and rewriting a report (exit 0 done, 3 interrupted)."""
    from osint_board.feeds.soak import EXIT_REFUSED, SoakConfig, SoakError, SoakRun, default_out_dir

    if hours <= 0:
        raise typer.BadParameter("must be more than 0", param_hint="--hours")
    directory = (out.expanduser() if out else default_out_dir()).absolute()
    config = SoakConfig(
        out=directory,
        hours=hours,
        only=list(only or []),
        sink=sink.value,
        report_every=report_every,
        sample_every=sample_every,
        state_file=state_file.expanduser().absolute() if state_file else None,
    )
    try:
        code = asyncio.run(SoakRun(config).run())
    except SoakError as exc:
        typer.echo(f"soak: {exc}", err=True)
        raise typer.Exit(EXIT_REFUSED) from None
    raise typer.Exit(code)


@soak_app.command("report")
def soak_report(
    directory: Annotated[Path, typer.Argument(help="a soak run directory (run.json + journal.ndjson)")],
    final: Annotated[
        bool, typer.Option("--final", help="mark the report FINAL even though the run never ended cleanly")
    ] = False,
) -> None:
    """Rebuild report.md / report.json of a soak run from its journal."""
    from osint_board.feeds.soak_report import REPORT_MD, RUN_META, write_report

    directory = directory.expanduser().absolute()
    if not (directory / RUN_META).is_file():
        typer.echo(f"soak: {directory} has no {RUN_META} (not a soak run directory)", err=True)
        raise typer.Exit(2)
    report = write_report(directory, final=final)
    status = report["status"] + (f" — {report['end_reason']}" if report.get("end_reason") else "")
    typer.echo(f"{report['verdict']} ({status}): {directory / REPORT_MD}")


@catalog_app.command("validate")
def catalog_validate() -> None:
    from osint_board.catalog import load_catalog

    cat = load_catalog()
    typer.echo(
        f"OK: {len(cat.modules)} modules, {len(cat.layers)} layers, {len(cat.services)} services, {len(cat.entities)} entity types"
    )


@catalog_app.command("stats")
def catalog_stats() -> None:
    from osint_board.modules.registry import get_registry

    reg = get_registry()
    typer.echo(json.dumps(reg.coverage(), indent=2))


@modules_app.command("list")
def modules_list(status: str | None = None, phase: int | None = None, consumes: str | None = None) -> None:
    from osint_board.modules.registry import get_registry

    for info in get_registry().all():
        if status and info.status.value != status:
            continue
        if phase and info.spec.phase != phase:
            continue
        if consumes and consumes not in info.spec.consumes:
            continue
        typer.echo(f"{info.status.value:12} p{info.spec.phase} {info.spec.mode:8} {info.spec.id:28} {info.spec.name}")


@modules_app.command("run")
def modules_run(module_id: str, entity_type: str, value: str, allow_active: bool = False, extract: bool = True) -> None:
    """Run a lookup module locally and print its emissions, then what the extractors find in them (no persistence)."""
    from osint_board.entities.types import EntityType
    from osint_board.modules.base import LookupModule, Scope
    from osint_board.modules.extraction import ExtractorPipeline
    from osint_board.modules.registry import get_registry
    from osint_board.modules.types import Emit, EntityRef
    from osint_board.worker.store import entity_meta

    def show(e: Emit, extracted_by: str | None = None) -> None:
        row = {"type": e.type.value, "value": e.value, "relation": e.relation, "confidence": e.confidence}
        if e.parent is not None:
            row["parent"] = f"{e.parent.type.value}:{e.parent.value}"
        if extracted_by:
            row["extracted_by"] = extracted_by
        typer.echo(json.dumps({**row, "meta": entity_meta(e)}, default=str))

    async def _main() -> None:
        registry = get_registry()
        mod = registry.instantiate(module_id, scope=Scope(allow_active=allow_active))
        if not isinstance(mod, LookupModule):
            raise typer.BadParameter(f"{module_id} is not a lookup module")
        target = EntityRef(EntityType(entity_type), value)
        mod.ctx.check_authorized(target)
        await mod.setup()
        emits = []
        async for e in mod.lookup(target):
            emits.append(e)
            show(e)
        if extract:
            for extractor_id, found in ExtractorPipeline(registry).run(emits).items():
                for e in found:
                    show(e, extractor_id)

    asyncio.run(_main())


@search_app.command("parse")
def search_parse(q: str) -> None:
    from osint_board.search.parser import parse_query

    typer.echo(json.dumps(parse_query(q).to_dict(), indent=2, default=str))


if __name__ == "__main__":
    app()
