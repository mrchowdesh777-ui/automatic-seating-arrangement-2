# ==========================================
# SEATING ALGORITHM - VERTICAL FILLING
# WITH SMART 3-BRANCH DIAGONAL PATTERN
# ==========================================

def generate_seating(branch_names, students_by_branch, rooms):

    allotment = []

    # --------------------------------------
    # Copy students branch-wise
    # --------------------------------------
    branches = {}

    for b in branch_names:
        branches[b] = students_by_branch.get(b, []).copy()

    # --------------------------------------
    # Active branches
    # --------------------------------------
    active = []

    for b in branch_names:
        if len(branches[b]) > 0:
            active.append(b)

    if len(active) == 0:
        return allotment

    # --------------------------------------
    # Initial 4-Branch Pattern
    # --------------------------------------
    pairA = [0, 1]
    pairB = [2, 3]

    next_branch = 4

    # --------------------------------------
    # 3 Branch Mode Controller
    # --------------------------------------
    three_branch_pattern = None

    # --------------------------------------
    # ROOM LOOP
    # --------------------------------------
    for room in rooms:

        room_id = room["room_id"]
        rows = room["num_rows"]
        cols = room["num_cols"]

        # ----------------------------------
        # COLUMN FIRST (Vertical Seating)
        # ----------------------------------
        for c in range(1, cols + 1):

            for r in range(1, rows + 1):

                # ----------------------------------
                # Find Remaining Branches
                # ----------------------------------
                remaining = []

                for b in active:
                    if len(branches[b]) > 0:
                        remaining.append(b)

                if len(remaining) == 0:
                    continue

                branch = None

                # ==================================================
                # 4 BRANCH MODE
                # ==================================================
                if len(remaining) >= 4:

                    # Reset 3-branch mode
                    three_branch_pattern = None

                    if r % 2 == 1:
                        current_pair = pairA
                    else:
                        current_pair = pairB

                    pos = 0 if c % 2 == 1 else 1

                    index = current_pair[pos]

                    if index >= len(active):
                        continue

                    branch = active[index]

                    while len(branches[branch]) == 0:

                        if next_branch >= len(active):
                            break

                        current_pair[pos] = next_branch

                        index = current_pair[pos]
                        branch = active[index]

                        next_branch += 1
                        break

                    if len(branches[branch]) == 0:
                        continue

                # ==================================================
                # 3 BRANCH MODE
                #
                # Largest branch becomes diagonal branch
                #
                # Col1 : A B A B A B
                # Col2 : C A C A C A
                # Col3 : A B A B A B
                # Col4 : C A C A C A
                #
                # Example:
                #
                # MECH EEE MECH EEE
                # ECE  MECH ECE  MECH
                # ==================================================
                elif len(remaining) == 3:

                    if three_branch_pattern is None:

                        sorted_branches = sorted(
                            remaining,
                            key=lambda x: len(branches[x]),
                            reverse=True
                        )

                        three_branch_pattern = {
                            "A": sorted_branches[0],  # Largest
                            "B": sorted_branches[1],
                            "C": sorted_branches[2]
                        }

                    A = three_branch_pattern["A"]
                    B = three_branch_pattern["B"]
                    C = three_branch_pattern["C"]

                    if c % 2 == 1:

                        # Odd Columns
                        if r % 2 == 1:
                            branch = A
                        else:
                            branch = B

                    else:

                        # Even Columns
                        if r % 2 == 1:
                            branch = C
                        else:
                            branch = A

                    # Fallback if one branch finishes
                    if len(branches[branch]) == 0:

                        remaining = [
                            b for b in active
                            if len(branches[b]) > 0
                        ]

                        if len(remaining) != 3:
                            three_branch_pattern = None
                            continue

                # ==================================================
                # 2 BRANCH MODE
                #
                # Checkerboard Pattern
                # ==================================================
                elif len(remaining) == 2:

                    three_branch_pattern = None

                    A = remaining[0]
                    B = remaining[1]

                    if (r + c) % 2 == 0:
                        branch = A
                    else:
                        branch = B

                # ==================================================
                # 1 BRANCH MODE
                # ==================================================
                else:

                    three_branch_pattern = None

                    branch = remaining[0]

                     # Odd columns -> Odd rows only
                    if c % 2 == 1:

                        if r % 2 == 0:
                            continue

                         # Even columns -> Even rows only
                    else:

                         if r % 2 == 1:
                            continue

                # ----------------------------------
                # Safety Check
                # ----------------------------------
                if branch is None:
                    continue

                if len(branches[branch]) == 0:
                    continue

                # ----------------------------------
                # Allocate Student
                # ----------------------------------
                student = branches[branch].pop(0)

                seat = {
                    "room_id": room_id,
                    "num_row": r,
                    "num_col": c,
                    "pin": student["pin_number"],
                    "student_id": student["student_id"],
                    "branch": branch
                }

                allotment.append(seat)

    return allotment