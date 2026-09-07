"""Sigmwah command-line interface."""

from __future__ import annotations

from pathlib import Path

import typer

from sigmwah import __version__
from sigmwah.config import ConvertSettings
from sigmwah.downloader import download_sigmahq
from sigmwah.exceptions import SigmwahError
from sigmwah.idalloc import IdAllocator
from sigmwah.service import convert_collection, load_sigma_paths, write_outputs
from sigmwah.validator import smoke_test_docker, validate_xml

app = typer.Typer(
    name="sigmwah",
    help="Convert Sigma rules (pySigma) into Wazuh 4.x XML rulesets.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"sigmwah {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Sigmwah — Sigma to Wazuh converter."""


@app.command()
def convert(
    paths: list[Path] = typer.Argument(..., help="Sigma YAML files or directories."),
    output: Path = typer.Option(Path("rules_sigma.xml"), "--output", "-o"),
    target: str = typer.Option("wazuh4", "--target", help="wazuh4 or wazuh5"),
    id_start: int = typer.Option(100100, "--id-start"),
    id_max: int = typer.Option(119999, "--id-max"),
    id_file: Path = typer.Option(Path(".sigmwah_ids.json"), "--id-file"),
    select: str | None = typer.Option(None, "--select"),
    tags: str | None = typer.Option(None, "--tags"),
    level: str | None = typer.Option(None, "--level", help="Minimum Sigma level, e.g. medium+"),
    exclude_tags: str | None = typer.Option(None, "--exclude-tags"),
    fmt: str = typer.Option("single", "--format", help="single | per-rule | per-group"),
    mappings: Path | None = typer.Option(None, "--mappings"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    strict: bool = typer.Option(False, "--strict"),
    fp_ignore: bool = typer.Option(False, "--fp-ignore"),
    report: Path | None = typer.Option(None, "--report"),
) -> None:
    """Convert Sigma rules to a Wazuh ruleset."""
    if target not in {"wazuh4", "wazuh5"}:
        raise typer.BadParameter("target must be wazuh4 or wazuh5")
    if fmt not in {"single", "per-rule", "per-group"}:
        raise typer.BadParameter("format must be single, per-rule, or per-group")
    settings = ConvertSettings(
        target=target,  # type: ignore[arg-type]
        id_start=id_start,
        id_max=id_max,
        id_file=id_file,
        select=select,
        tags=[part.strip() for part in tags.split(",")] if tags else [],
        level=level,
        exclude_tags=[part.strip() for part in exclude_tags.split(",")] if exclude_tags else [],
        output_format=fmt,  # type: ignore[arg-type]
        mappings_file=mappings,
        dry_run=dry_run,
        strict=strict,
        fp_ignore=fp_ignore,
        report_path=report,
    )
    try:
        collection = load_sigma_paths(paths)
        items, conv_report, _allocator = convert_collection(collection, settings)
        written = write_outputs(items, output, settings)
    except (SigmwahError, ValueError) as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc
    if settings.report_path is not None:
        conv_report.write(settings.report_path)
        typer.echo(f"Wrote report {settings.report_path}")
    else:
        typer.echo(conv_report.to_markdown())
    if settings.strict and conv_report.skipped:
        typer.secho("Strict mode: one or more rules were skipped.", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    for path in written:
        action = "Would write" if dry_run else "Wrote"
        typer.echo(f"{action} {path}")


@app.command("download-sigmahq")
def download_sigmahq_cmd(
    version: str = typer.Option("latest", "--version"),
    dest: Path = typer.Option(Path("sigmahq"), "--dest", help="Directory to extract into"),
) -> None:
    """Download a SigmaHQ release zip. Does not vendor rules into Sigmwah."""
    try:
        extracted = download_sigmahq(dest, version=version)
    except SigmwahError as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Extracted SigmaHQ rules to {extracted}")
    typer.echo("Rules remain under Detection Rule License 1.1. See SIGMWAH_DRL_NOTICE.txt.")


@app.command()
def validate(
    rules: Path = typer.Argument(..., help="Wazuh XML ruleset to validate"),
    docker: bool = typer.Option(False, "--docker", help="Run wazuh-logtest in Docker"),
    event: list[str] = typer.Option([], "--event", help="Synthetic log line for logtest"),
) -> None:
    """Validate XML well-formedness and optionally smoke-test with wazuh-logtest."""
    result = validate_xml(rules)
    if docker:
        result = smoke_test_docker(rules, event)
    for message in result.messages:
        typer.echo(message)
    docker_errors = (
        docker
        and result.docker_ran
        and any("error" in message.lower() for message in result.messages)
    )
    if not result.well_formed or docker_errors:
        raise typer.Exit(code=1)
    typer.echo(f"XML well-formed: {result.well_formed}")
    if result.docker_ran:
        typer.echo("Docker smoke test completed")


@app.command()
def ids(
    id_file: Path = typer.Option(Path(".sigmwah_ids.json"), "--id-file"),
    csv_out: Path | None = typer.Option(None, "--csv", help="Export allocations to CSV"),
    id_start: int = typer.Option(100100, "--id-start"),
    id_max: int = typer.Option(119999, "--id-max"),
) -> None:
    """List allocated Wazuh rule IDs."""
    allocator = IdAllocator(id_file, id_start=id_start, id_max=id_max)
    rows = allocator.list_allocations()
    if not rows:
        typer.echo("No IDs allocated yet.")
        return
    for row in rows:
        typer.echo(f"{row.wazuh_id}\t{row.sigma_key}\t{row.title}")
    if csv_out is not None:
        allocator.export_csv(csv_out)
        typer.echo(f"Wrote {csv_out}")
