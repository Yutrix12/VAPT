"""Draw Trivy-style text (table) reports for the tests, with merged cells.

A cell is a string, a list of lines, or None. None means "merged with the cell
above": Trivy leaves it empty and draws no line between the two cells.
"""

from collections.abc import Sequence

Cell = str | list[str] | None

SUMMARY_HEADER = ["Target", "Type", "Vulnerabilities", "Misconfigurations", "Secrets", "Licenses"]
VULN_HEADER = ["Library", "Vulnerability", "Severity", "Status", "Installed Version", "Fixed Version", "Title"]
LICENSE_HEADER = ["Package", "License", "Classification", "Severity"]


def lines_of(cell: Cell) -> list[str]:
    if cell is None:
        return []
    return [cell] if isinstance(cell, str) else list(cell)


def box(header: Sequence[str], rows: Sequence[Sequence[Cell]]) -> str:
    """A box table like Trivy's: one border character per column."""
    widths = [len(name) for name in header]
    for row in rows:
        for column, cell in enumerate(row):
            for line in lines_of(cell):
                widths[column] = max(widths[column], len(line))
    widths = [width + 2 for width in widths]

    def border(left: str, middle: str, right: str, breaks: Sequence[bool]) -> str:
        parts = [("─" if breaks[column] else " ") * width for column, width in enumerate(widths)]
        return left + middle.join(parts) + right

    def content(cells: Sequence[Cell], centered: bool) -> list[str]:
        columns = [lines_of(cell) for cell in cells]
        height = max(1, max(len(lines) for lines in columns))
        out = []
        for number in range(height):
            texts = []
            for column, width in enumerate(widths):
                text = columns[column][number] if number < len(columns[column]) else ""
                texts.append(f" {text.center(width - 2) if centered else text.ljust(width - 2)} ")
            out.append("│" + "│".join(texts) + "│")
        return out

    everything = [True] * len(header)
    out = [border("┌", "┬", "┐", everything)]
    out += content(list(header), centered=True)
    out.append(border("├", "┼", "┤", everything))
    for number, row in enumerate(rows):
        out += content(row, centered=False)
        if number + 1 < len(rows):
            out.append(border("├", "┼", "┤", [cell is not None for cell in rows[number + 1]]))
    out.append(border("└", "┴", "┘", everything))
    return "\n".join(out)


def summary(rows: Sequence[Sequence[str]]) -> str:
    """The "Report Summary" part that opens a scan's table output."""
    legend = "Legend:\n- '-': Not scanned\n- '0': Clean (no security findings detected)"
    return f"\nReport Summary\n\n{box(SUMMARY_HEADER, rows)}\n{legend}\n\n"


def section(heading: str, *parts: str) -> str:
    """A result: heading, a line of '=', then the given parts."""
    return f"\n{heading}\n{'=' * len(heading)}\n" + "\n".join(parts) + "\n\n"


def totals(unknown: int = 0, low: int = 0, medium: int = 0, high: int = 0, critical: int = 0) -> str:
    total = unknown + low + medium + high + critical
    return (f"Total: {total} (UNKNOWN: {unknown}, LOW: {low}, MEDIUM: {medium}, "
            f"HIGH: {high}, CRITICAL: {critical})\n")


def misconfig_block(check_id: str, severity: str, title: str, description: str, url: str,
                    code: Sequence[str] = ()) -> str:
    """One failed check. `code` are the source lines Trivy prints after it."""
    lines = [f"{check_id} ({severity}): {title}", "═" * 40, description, "", f"See {url}", "─" * 40]
    if code:
        lines += [" Dockerfile:3-4", "─" * 40, *code, "─" * 40]
    return "\n".join(lines) + "\n\n"


def secret_block(severity: str, category: str, rule: str, title: str, location: str = "",
                 code: Sequence[str] = ()) -> str:
    """One secret. `code` are the source lines Trivy prints around it."""
    lines = [f"{severity}: {category} ({rule})", "═" * 40, title, "─" * 40]
    if location:
        lines += [f" {location}", "─" * 40, *code, "─" * 40]
    return "\n".join(lines) + "\n\n"
