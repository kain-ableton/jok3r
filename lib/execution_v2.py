#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import asyncio
from typing import Any, Dict, List
from .async_runtime import ToolCommand, ToolResult, run_many

def build_commands_from_plan(plan: List[Dict[str, Any]]) -> List[ToolCommand]:
    commands: List[ToolCommand] = []
    for item in plan:
        commands.append(ToolCommand(
            name=str(item["tool"]),
            argv=list(item["argv"]),
            stage=str(item.get("stage", "unknown")),
            timeout=int(item.get("timeout", 1200)),
            meta=dict(item.get("meta", {})),
        ))
    return commands

async def run_plan_async(plan: List[Dict[str, Any]], max_concurrent: int = 8) -> List[ToolResult]:
    commands = build_commands_from_plan(plan)
    return await run_many(commands, max_concurrent=max_concurrent)

def run_plan(plan: List[Dict[str, Any]], max_concurrent: int = 8) -> List[ToolResult]:
    return asyncio.run(run_plan_async(plan, max_concurrent=max_concurrent))
