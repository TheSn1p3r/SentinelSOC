"""SentinelSOC — a local Windows SOC agent.

Collects Windows telemetry (Event Log, processes, network connections),
runs it through a local, offline detection engine, scores risk, and
exposes a dashboard + API for analyst-approved response actions
(process termination, file quarantine).
"""

__version__ = "1.0.0"
__app_name__ = "SentinelSOC"
