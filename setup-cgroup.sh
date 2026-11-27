
#!/usr/bin/env bash
set -euo pipefail

# Phase 1: Enter a delegated systemd scope.
if [[ "${1:-}" != "--inside" ]]; then
    echo "[1/4] Creating delegated systemd scope..."

    exec sudo systemd-run \
        --scope \
        -p Delegate=yes \
        -p TasksMax=infinity \
        -- /bin/bash "$0" --inside
fi

# Phase 2: Resolve cgroup v2 path.
if [[ "$(stat -fc %T /sys/fs/cgroup)" != "cgroup2fs" ]]; then
    echo "ERROR: cgroup v2 is required."
    exit 1
fi

CGROUP_ROOT="/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)"
export CGROUP_ROOT

echo "[2/4] CGROUP_ROOT=$CGROUP_ROOT"

# Phase 3: Move the current shell into a leaf cgroup.
mkdir -p "$CGROUP_ROOT/runtime"
echo "$$" > "$CGROUP_ROOT/runtime/cgroup.procs"

# The delegated root must have no direct processes.
if [[ -s "$CGROUP_ROOT/cgroup.procs" ]]; then
    echo "ERROR: Scope root still contains processes:"
    cat "$CGROUP_ROOT/cgroup.procs"
    exit 1
fi

# Phase 4: Enable controllers for child cgroups.
echo "[3/4] Enabling cpu, memory, pids..."
echo "+cpu +memory +pids" > "$CGROUP_ROOT/cgroup.subtree_control"

echo "[4/4] Environment ready!"
echo
echo "CGROUP_ROOT=$CGROUP_ROOT"
echo "Controllers: $(cat "$CGROUP_ROOT/cgroup.subtree_control")"
echo "Shell cgroup: $(cat /proc/$$/cgroup)"
echo

# Keep an interactive shell inside the delegated scope.
exec /bin/bash -i

