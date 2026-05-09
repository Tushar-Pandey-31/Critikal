"""
Unified CLI entry point for Critikal.

Dispatch modes:
  critikal                            → TUI (interactive)
  critikal --repo <url>               → headless full pipeline audit
  critikal --repo <url> --interactive → TUI with pre-loaded repo
  critikal --headless "<prompt>"      → headless agentic mode (custom prompt)
  critikal --legacy --repo <url>      → old coordinator_node() pipeline (deprecated)
  critikal --dream <engagement_id>    → run memory consolidation
  critikal --schedule "cron" --repo u → schedule a recurring audit
  critikal --list-schedules           → list all scheduled tasks

  python -m src.main --repo <url>     → still works (backward compat)
"""

import argparse
import asyncio
import logging
import os
import sys
import warnings

# Load .env before anything else reads os.environ. We do this at import
# time so every code path (headless, TUI, legacy, scheduler) sees the
# same environment without each entry point remembering to call it.
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Critikal — autonomous security research agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--repo",
        type=str,
        help="Repository URL or local path to audit",
    )
    parser.add_argument(
        "--headless",
        type=str,
        nargs="?",
        const="",
        help="Run in headless mode with optional custom prompt",
    )
    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Force interactive TUI mode",
    )
    parser.add_argument(
        "--legacy",
        action="store_true",
        help="[DEPRECATED] Use the old coordinator_node() pipeline",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=os.getenv("AGENT_MODEL_NAME"),
        help="Model for the agent brain (default: $AGENT_MODEL_NAME or grok-4-1-fast-reasoning)",
    )
    parser.add_argument(
        "--budget",
        type=float,
        default=None,
        help="Maximum budget in USD for this session",
    )
    parser.add_argument(
        "--permission-mode",
        choices=["ask", "auto", "yolo"],
        default="auto",
        help="Permission mode (default: auto)",
    )
    parser.add_argument(
        "--resume",
        type=str,
        help="Resume a previous engagement by ID",
    )
    parser.add_argument(
        "--auto-ingest",
        action="store_true",
        help="Auto-ingest RAG knowledge base on first run",
    )

    # ── Phase 7: Scheduler ──
    parser.add_argument(
        "--schedule",
        type=str,
        help="Cron expression to schedule a recurring audit (e.g., '0 0 * * 1')",
    )
    parser.add_argument(
        "--list-schedules",
        action="store_true",
        help="List all scheduled tasks",
    )
    parser.add_argument(
        "--remove-schedule",
        type=str,
        help="Remove a scheduled task by ID",
    )
    parser.add_argument(
        "--run-scheduler",
        action="store_true",
        help="Start the background scheduler daemon",
    )

    # ── Phase 5: Memory ──
    parser.add_argument(
        "--dream",
        type=str,
        nargs="?",
        const="",
        help="Run memory consolidation for an engagement ID",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose logging",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Configure logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    # ── Memory consolidation ──
    if args.dream is not None:
        _run_dream(args)
        return

    # ── Scheduler commands ──
    if args.list_schedules:
        _list_schedules()
        return

    if args.remove_schedule:
        _remove_schedule(args.remove_schedule)
        return

    if args.run_scheduler:
        _run_scheduler()
        return

    if args.schedule:
        _add_schedule(args)
        return

    # ── Legacy mode (deprecated) ──
    if args.legacy:
        warnings.warn(
            "The --legacy flag is deprecated and will be removed in a future release. "
            "The new agentic system is now the default.",
            DeprecationWarning,
            stacklevel=2,
        )
        print("⚠️  --legacy is deprecated. Using old LangGraph pipeline.")
        if not args.repo:
            parser.error("--legacy requires --repo")
        sys.argv = ["critikal", "--repo", args.repo]
        if args.auto_ingest:
            sys.argv.append("--auto-ingest")
        from src.main import main as legacy_main

        legacy_main()
        return

    # ── Headless mode ──
    if args.headless is not None or (args.repo and not args.interactive):
        _run_headless(args)
        return

    # ── Interactive TUI mode ──
    _run_tui(args)


def _run_headless(args):
    """Run in headless mode."""
    from src.agent.headless import HeadlessRunner

    runner = HeadlessRunner(
        model=args.model,
        permission_mode=args.permission_mode,
        budget_usd=args.budget,
        engagement_id=args.resume,
    )

    if args.repo:
        result = asyncio.run(runner.run_audit(args.repo))
    elif args.headless:
        result = asyncio.run(runner.run_prompt(args.headless))
    else:
        print("Error: provide --repo or --headless with a prompt.")
        sys.exit(1)

    print("\n" + result)


def _run_tui(args):
    """Launch the interactive TUI."""
    try:
        from src.tui.app import CritikalApp
    except ImportError:
        print(
            "TUI dependencies not installed. Install with:\n"
            "  poetry add textual\n"
            "\nOr run in headless mode:\n"
            "  critikal --repo <url>\n"
            "  critikal --headless '<prompt>'"
        )
        sys.exit(1)

    # ── CRITICAL: Redirect ALL logging to a file when TUI is active ──
    # Python logging writes to stderr by default, which corrupts the
    # Textual terminal. Redirect everything to a log file.
    import pathlib

    log_dir = pathlib.Path(os.path.expanduser("~/.critikal/logs"))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "tui_session.log"

    # Remove all existing handlers from root logger
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add file handler only
    file_handler = logging.FileHandler(str(log_file), mode="a")
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s", datefmt="%H:%M:%S"))
    root_logger.addHandler(file_handler)
    root_logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    # Silence noisy third-party loggers
    for noisy in ("httpx", "httpcore", "anthropic", "urllib3", "chromadb.telemetry"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    app = CritikalApp(
        repo_url=args.repo,
        model=args.model,
        budget_usd=args.budget,
        permission_mode=args.permission_mode,
        resume_engagement=args.resume,
    )
    app.run()


def _run_dream(args):
    """Run memory consolidation."""
    engagement_id = args.dream
    if not engagement_id:
        # List available engagements
        from src.agent.memory.session_memory import MEMORY_BASE_DIR

        if MEMORY_BASE_DIR.exists():
            engagements = [d.name for d in MEMORY_BASE_DIR.iterdir() if d.is_dir()]
            if engagements:
                print("Available engagements:")
                for eid in sorted(engagements):
                    session_file = MEMORY_BASE_DIR / eid / "session.jsonl"
                    count = sum(1 for _ in open(session_file)) if session_file.exists() else 0
                    has_consolidated = (MEMORY_BASE_DIR / eid / "consolidated.md").exists()
                    status = "📄 consolidated" if has_consolidated else "📝 raw"
                    print(f"  {eid}  ({count} memories, {status})")
            else:
                print("No engagements found.")
        else:
            print("No memory directory found.")
        return

    print(f"Running memory consolidation for engagement: {engagement_id}")
    from src.agent.memory.auto_dream import run_dream

    result = asyncio.run(run_dream(engagement_id))
    if result:
        print("✓ Consolidation complete")
    else:
        print("✗ Nothing to consolidate (or lock held)")


def _list_schedules():
    """List all scheduled tasks."""
    from src.agent.scheduler import CronScheduler

    scheduler = CronScheduler()
    print(scheduler.format_schedule_table())


def _remove_schedule(task_id: str):
    """Remove a scheduled task."""
    from src.agent.scheduler import CronScheduler

    scheduler = CronScheduler()
    if scheduler.remove_task(task_id):
        print(f"✓ Removed task {task_id}")
    else:
        print(f"✗ Task {task_id} not found")


def _add_schedule(args):
    """Add a new scheduled task."""
    from src.agent.scheduler import CronScheduler, ScheduledTask

    if not args.repo and not args.headless:
        print("Error: --schedule requires --repo or --headless")
        sys.exit(1)

    task = ScheduledTask(
        repo_url=args.repo or "",
        cron_expr=args.schedule,
        prompt=args.headless or "",
        model=args.model or "",
        budget_usd=args.budget,
    )

    scheduler = CronScheduler()
    task_id = scheduler.add_task(task)
    print(f"✓ Scheduled task {task_id}: {args.schedule}")
    print(f"  Repo: {args.repo or '(custom prompt)'}")
    print("  Run scheduler with: critikal --run-scheduler")


def _run_scheduler():
    """Start the background scheduler daemon."""
    from src.agent.scheduler import CronScheduler

    scheduler = CronScheduler()
    tasks = scheduler.list_tasks()
    if not tasks:
        print("No scheduled tasks. Add one with:")
        print("  critikal --schedule '0 0 * * 1' --repo <url>")
        return

    print(f"Starting scheduler with {len(tasks)} task(s)...")
    print("Press Ctrl+C to stop.")
    try:
        asyncio.run(scheduler.start())
    except KeyboardInterrupt:
        print("\nScheduler stopped.")


if __name__ == "__main__":
    main()
