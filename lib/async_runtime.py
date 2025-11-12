#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List

@dataclass
class ToolCommand:
    name: str
    argv: List[str]
    stage: str
    timeout: int = 1200
    meta: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ToolResult:
    name: str
    stage: str
    rc: int
    stdout: str
    stderr: str
    timeout: bool
    meta: Dict[str, Any]

async def _run_one(cmd: ToolCommand) -> ToolResult:
    proc = await asyncio.create_subprocess_exec(
        *cmd.argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=cmd.timeout)
        timed_out = False
        rc = proc.returncode
    except asyncio.TimeoutError:
        proc.kill()
        out, err = b"", f"timeout after {cmd.timeout}s".encode("utf-8")
        timed_out = True
        rc = 124
    return ToolResult(
        name=cmd.name,
        stage=cmd.stage,
        rc=rc,
        stdout=out.decode("utf-8", "ignore"),
        stderr=err.decode("utf-8", "ignore"),
        timeout=timed_out,
        meta=cmd.meta,
    )

async def run_many(commands: List[ToolCommand], max_concurrent: int = 8) -> List[ToolResult]:
    sem = asyncio.Semaphore(max_concurrent)
    async def _wrapped(c: ToolCommand) -> ToolResult:
        async with sem:
            return await _run_one(c)
    tasks = [_wrapped(c) for c in commands]
    return await asyncio.gather(*tasks)
