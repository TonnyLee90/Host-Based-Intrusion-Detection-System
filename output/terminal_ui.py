from datetime import datetime
from IDS.alert_manager import runtime_alerts
"""
Print an alert summary for the just-completed scan cycle.

Reads from alert_manager.runtime_alerts, which is populated by
alert_manager.alert() and cleared at the start of each scan.

Args: scan_num: The current scan cycle number.
"""
def render_terminal_ui(scan_num: int) -> None:
    sep = "=" * 60
    print(f"\n{sep}")
    print(f"  SCAN #{scan_num} COMPLETE  —  {len(runtime_alerts)} alert(s)")
    print(sep)
    for entry in runtime_alerts:
        print(
            f"  [{entry['severity']}] [{entry['category']}] {entry['message']}"
        )
    print(sep + "\n")