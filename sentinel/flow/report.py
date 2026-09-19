"""One text line per flow."""

from sentinel.flow.table import Flow, FlowTable
from sentinel.summary import describe_app

_ARROWS = ("->", "<-")


def format_flow(flow: Flow) -> str:
    """`tcp c > s: state, pkts c/s, bytes c/s, 0.014000s [notes] | -> app | <- app`."""
    parts = [f"{flow.state}"] if flow.state else []
    parts += [
        f"pkts {flow.packets[0]}/{flow.packets[1]}",
        f"bytes {flow.payload_bytes[0]}/{flow.payload_bytes[1]}",
        f"{flow.duration_ns / 1e9:.6f}s",
    ]
    line = f"{flow.proto} {flow.client} > {flow.server}: " + ", ".join(parts)
    line += "".join(f" [{note}]" for note in flow.notes())
    for item in flow.app():
        line += f" | {_ARROWS[item.direction]} {describe_app(item.layer)}"
        line += "".join(f" [{a}]" for a in item.layer.anomalies)
        if item.layer.error:
            line += f" [error: {item.layer.error}]"
    return line


def format_footer(table: FlowTable) -> str:
    in_flows = sum(sum(f.packets) for f in table.flows)
    line = (
        f"# {len(table.flows)} flows, {in_flows} packets in flows, "
        f"{table.skipped_packets} not in a flow"
    )
    if table.untracked_packets:
        line += f", {table.untracked_packets} packets not tracked (flow limit)"
    return line
