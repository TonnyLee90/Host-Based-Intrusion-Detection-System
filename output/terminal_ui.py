from datetime import datetime
from IDS.alert_manager import runtime_alerts

# Print an alert summary
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