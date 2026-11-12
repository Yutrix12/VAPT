"""Read the box tables of Trivy's text output, following merged cells.

Trivy merges equal neighbouring cells downwards. A border line segment made
of "─" ends the cell above; a segment of spaces means the cell continues.
The text of a merged cell sits in its first block of lines.
"""

from app.parsers.models import ReportError

SIDE = "│"
RULE = "─"
# Characters that appear at a column boundary only on a border line.
JUNCTIONS = "├┤┼┴└┘"

# A table row: for each column, the lines of the cell group it belongs to.
Row = list[list[str]]


def read_table(lines: list[str], start: int, where: str) -> tuple[list[str], list[Row], int]:
    """Read the table whose top border is lines[start].

    Returns the header names, the rows and the index of the line after the
    table. Raises ReportError with a one-line reason for a broken table.
    """
    top = lines[start].rstrip()
    bounds = [i for i, char in enumerate(top) if char in "┌┬┐"]
    columns = len(bounds) - 1
    if columns < 1:
        raise ReportError(f"{where}: the table has no columns")
    blocks: list[tuple[list[bool], list[list[str]]]] = []  # (breaks above, text lines)
    breaks = [True] * columns
    text_lines: list[list[str]] = []
    index = start + 1
    while index < len(lines):
        line = lines[index].rstrip()
        if is_border(line, bounds):
            blocks.append((breaks, text_lines))
            text_lines = []
            if line.startswith("└"):
                return rows_from_blocks(blocks, columns, where) + (index + 1,)
            breaks = [segment_breaks(line, bounds, column) for column in range(columns)]
        elif line.startswith(SIDE):
            cells = [cell.strip() for cell in line.split(SIDE)[1:-1]]
            if len(cells) != columns:
                raise ReportError(f"{where}: a table row has {len(cells)} cells, expected {columns}")
            text_lines.append(cells)
        else:
            raise ReportError(f"{where}: a table is not closed")
        index += 1
    raise ReportError(f"{where}: a table is not closed")


def is_border(line: str, bounds: list[int]) -> bool:
    """A border line has a junction character at a column boundary.

    It can start with "│" when the first column is merged, so the first
    character alone does not tell a border from a row of text.
    """
    return any(bound < len(line) and line[bound] in JUNCTIONS for bound in bounds)


def segment_breaks(line: str, bounds: list[int], column: int) -> bool:
    """True if the border line ends the cell above this column (a run of ─)."""
    segment = line[bounds[column] + 1 : bounds[column + 1]]
    return segment != "" and set(segment) == {RULE}


def rows_from_blocks(
    blocks: list[tuple[list[bool], list[list[str]]]], columns: int, where: str
) -> tuple[list[str], list[Row]]:
    """Header names and, per block, the merged cell lines of every column."""
    if not blocks:
        raise ReportError(f"{where}: the table has no header")
    header = [" ".join(line[column] for line in blocks[0][1] if line[column]) for column in range(columns)]
    groups: list[list[list[str]]] = [[] for _ in range(columns)]  # per column: the cell groups
    rows: list[list[int]] = []  # per block: the group number of each column
    for breaks, text_lines in blocks[1:]:
        for column in range(columns):
            if breaks[column] or not groups[column]:
                groups[column].append([])
        rows.append([len(groups[column]) - 1 for column in range(columns)])
        for column in range(columns):
            groups[column][-1].extend(line[column] for line in text_lines if line[column])
    return header, [[groups[column][number] for column, number in enumerate(row)] for row in rows]
