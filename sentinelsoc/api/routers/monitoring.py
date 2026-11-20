from __future__ import annotations

import psutil
from fastapi import APIRouter, Depends, Request

from sentinelsoc.api.auth import require_api_auth

router = APIRouter(dependencies=[Depends(require_api_auth)])


@router.get("/processes")
def live_processes(limit: int = 300):
    out = []
    for p in psutil.process_iter(["pid", "ppid", "name", "username", "create_time", "exe"]):
        try:
            info = p.info
            try:
                info["cpu_percent"] = p.cpu_percent(interval=None)
                info["memory_mb"] = round(p.memory_info().rss / (1024 * 1024), 1)
            except psutil.Error:
                info["cpu_percent"] = None
                info["memory_mb"] = None
            out.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    out.sort(key=lambda r: r.get("memory_mb") or 0, reverse=True)
    return {"processes": out[:limit]}


@router.get("/processes/history")
def process_history(request: Request, limit: int = 200):
    return {"processes": request.app.state.agent.db.get_processes_history(limit=limit)}


@router.get("/network")
def live_network(limit: int = 300):
    out = []
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return {"connections": [], "warning": "Insufficient privileges to list all connections."}
    for c in conns:
        if not c.raddr:
            continue
        proc_name = None
        if c.pid:
            try:
                proc_name = psutil.Process(c.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                proc_name = None
        out.append({
            "pid": c.pid,
            "process_name": proc_name,
            "local_addr": c.laddr.ip if c.laddr else None,
            "local_port": c.laddr.port if c.laddr else None,
            "remote_addr": c.raddr.ip,
            "remote_port": c.raddr.port,
            "protocol": "tcp" if c.type == 1 else "udp",
            "status": c.status,
        })
    return {"connections": out[:limit]}


@router.get("/network/history")
def network_history(request: Request, limit: int = 200):
    return {"connections": request.app.state.agent.db.get_network_history(limit=limit)}
