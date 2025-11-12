# Modern async runner overlay for Jok3r

This overlay keeps the original Jok3r layout and adds an asyncio-based runner that you can enable with CLI flags.

## Included
- lib/async_runtime.py
- lib/execution_v2.py
- lib/db_v2.py
- lib/modern_runner_patch.py
- scripts/apply_async_rebase.sh
- README_MODERN.md

## Minimal wiring
1) Add to lib/core/ArgumentsParser.py inside the 'Running option' group:

    running.add_argument('--modern-runner', action='store_true', dest='modern_runner',
                         help='Use asyncio-based modern runner', default=False)
    running.add_argument('--modern-max-concurrent', type=int, dest='modern_max_concurrent',
                         help='Max concurrent commands for modern runner', default=8)

2) Before checks run:
    from lib.modern_runner_patch import enable as _enable_modern_runner
    if args.modern_runner:
        _enable_modern_runner(getattr(args, 'modern_max_concurrent', 8))

3) Test:
    python3 jok3r.py attack -t https://example.com -s http --fast --modern-runner --modern-max-concurrent 8
