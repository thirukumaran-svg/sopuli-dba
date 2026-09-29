#!/bin/bash
# sopuli-dba : bring up oracle-19c-ru (19.19.0.0.0 EE, arm64) on an Ampere A1 VM (#565)
#
# Runs ON the VM that new-a1-host.ps1 created, as `opc`, after the repository's
# test/ and sql/ directories were copied to ~/sopuli/ (the .ps1 prints the scp).
# Run it with `ssh -t` if the registry login has not been done: the login
# prompts, and without a terminal docker refuses to read a password. Having run
# `ssh -t opc@<ip> sudo docker login container-registry.oracle.com` first, it
# needs no terminal at all.
# Oracle Linux 9, aarch64. Re-runnable: every step checks before it acts.
#
#   1. installs Docker CE and the compose plugin, if absent;
#   2. logs in to container-registry.oracle.com, if the image is not already
#      here -- interactively, and the password is typed at docker's prompt,
#      never passed as an argument (invariant 1's reason, applied to docker);
#   3. starts test/compose.yaml's oracle-19c-ru with the listener bound to
#      127.0.0.1 only, through compose.oci.yaml beside it. The security list
#      already admits nothing but SSH; this is the second fence, because Docker
#      publishes ports around firewalld;
#   4. waits for healthy, TIMING it -- first-start time is one of #565's numbers;
#   5. prints what the database says about itself: banner, PDB state, whether
#      PASSWORD_ROLLOVER_TIME exists (the capability probe sopuli runs), and the
#      SOPULI_* profiles the init wrapper created.
#
# It measures nothing else. Rollover, verifiers and the leak probe are #565's
# next step, run against this through an SSH tunnel.
#
# Output goes to the terminal and to ~/sopuli/565-setup.log.

set -euo pipefail

ROOT="$HOME/sopuli"
TEST="$ROOT/test"
LOG="$ROOT/565-setup.log"
IMAGE="container-registry.oracle.com/database/enterprise:19.19.0.0"
CONTAINER="sopuli-test-oracle-19c-ru-1"
WAIT_MINUTES=90

mkdir -p "$ROOT"
exec > >(tee -a "$LOG") 2>&1
echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) setup-oracle-19c.sh"

say() { printf '\n--- %s\n' "$*"; }
die() { printf '\nFAILED: %s\n' "$*" >&2; exit 1; }

# ------------------------------------------------------------ preflight ---

[ "$(uname -m)" = "aarch64" ] || die "this is $(uname -m), not aarch64 -- the 19.19 image does not start under emulation (#565)"
[ -f "$TEST/compose.yaml" ] || die "no $TEST/compose.yaml -- from the repository root on your machine: ssh opc@<ip> mkdir -p sopuli && scp -r test sql opc@<ip>:sopuli/"
[ -d "$TEST/oracle-init-19c" ] || die "no $TEST/oracle-init-19c -- copy the whole test/ directory, not just compose.yaml"

# ------------------------------------------------------------- docker -----

if ! command -v docker >/dev/null 2>&1; then
    say "installing Docker CE"
    sudo dnf -y install dnf-plugins-core
    sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi
sudo systemctl enable --now docker

# sudo throughout, rather than the docker group: a group added in this session
# does not apply to it, and a second login just for that is a step to forget.
DOCKER="sudo docker"

# !override in compose.oci.yaml needs compose 2.24.4 or later.
say "versions"
$DOCKER version --format 'docker {{.Server.Version}} ({{.Server.Arch}})'
$DOCKER compose version

# --------------------------------------------------------------- image ----

if ! $DOCKER image inspect "$IMAGE" >/dev/null 2>&1; then
    # Pull first and log in only if refused, so a login done beforehand in its
    # own `ssh -t ... sudo docker login container-registry.oracle.com` lets
    # the rest of this script run without a terminal.
    say "pulling $IMAGE (about 3 GB; ~10 GB unpacked)"
    if ! $DOCKER pull "$IMAGE"; then
        [ -t 0 ] || die "the registry refused the pull and there is no terminal to log in from -- run: ssh -t opc@<ip> sudo docker login container-registry.oracle.com"
        say "logging in to container-registry.oracle.com"
        echo "Username is your Oracle account email. Type the password at the prompt."
        echo "The licence for Database -> enterprise must already be accepted on the registry."
        $DOCKER login container-registry.oracle.com
        $DOCKER pull "$IMAGE"
    fi
    # docker keeps the login base64-encoded in /root/.docker/config.json; the
    # image is here now, so nothing needs it.
    $DOCKER logout container-registry.oracle.com || true
fi
say "image"
$DOCKER image inspect "$IMAGE" --format '{{.Os}}/{{.Architecture}}  {{index .RepoDigests 0}}  created {{.Created}}'

# ------------------------------------------------------------- compose ----

# Listener on loopback only. !override replaces the base file's ports list
# rather than appending to it, which is what a plain override would do.
cat > "$TEST/compose.oci.yaml" <<'YAML'
# Written by oci-a1/setup-oracle-19c.sh. Binds 19.19's listener to loopback, so
# it is reached through `ssh -L 1527:127.0.0.1:1527`, never from the internet.
services:
  oracle-19c-ru:
    ports: !override ["127.0.0.1:1527:1521"]
YAML

# Oracle Linux 9's standard image enforces SELinux, and test/ sits under
# /home/opc as user_home_t, which a container may not read, so the init
# wrapper's scripts would be denied. Relabel the two bind-mounted directories
# here rather than adding :z to the mounts, so the override does not have to
# restate compose.yaml's volume list.
if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
    say "relabelling the init directories for SELinux ($(getenforce))"
    sudo chcon -R -t container_file_t "$TEST/oracle-init" "$TEST/oracle-init-19c"
fi

COMPOSE="$DOCKER compose -f $TEST/compose.yaml -f $TEST/compose.oci.yaml --profile oracle19c-ru"

state=$($DOCKER inspect -f '{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$CONTAINER" 2>/dev/null || echo "absent/")
if [ "$state" = "running/healthy" ]; then
    say "$CONTAINER is already healthy; not restarting it"
else
    say "starting $CONTAINER (was: $state)"
    start=$(date +%s)
    $COMPOSE up -d
    $DOCKER port "$CONTAINER"

    say "waiting for healthy, up to $WAIT_MINUTES min (first start runs DBCA)"
    last=""
    while :; do
        now=$(date +%s); elapsed=$(( now - start ))
        st=$($DOCKER inspect -f '{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$CONTAINER")
        progress=$($DOCKER logs "$CONTAINER" 2>&1 | grep -E '% complete' | tail -1 || true)
        if [ -n "$progress" ] && [ "$progress" != "$last" ]; then
            printf '  %4ds  %s\n' "$elapsed" "$progress"; last="$progress"
        fi
        case "$st" in
            running/healthy) break ;;
            exited/*|dead/*) $DOCKER logs --tail 40 "$CONTAINER"; die "container stopped: $st" ;;
        esac
        if $DOCKER logs "$CONTAINER" 2>&1 | grep -qE 'DATABASE SETUP WAS NOT SUCCESSFUL|ORA-01096|ORA-00443'; then
            $DOCKER logs --tail 40 "$CONTAINER"; die "DBCA failed -- see above"
        fi
        [ "$elapsed" -lt $(( WAIT_MINUTES * 60 )) ] || die "not healthy after $WAIT_MINUTES min"
        sleep 30
    done
    elapsed=$(( $(date +%s) - start ))
    say "HEALTHY after $(( elapsed / 60 )) min $(( elapsed % 60 )) s  ($(nproc) CPUs, $(free -g | awk '/^Mem:/{print $2}') GB)"
fi

# -------------------------------------------------------------- report ----

say "what the database says"
$DOCKER exec -i "$CONTAINER" bash -c 'sqlplus -s / as sysdba' <<'SQL' || die "the report query failed -- see the ORA- above; nothing after it is a measurement"
whenever sqlerror exit failure
whenever oserror exit failure
set pagesize 100 linesize 200 feedback off heading on
column banner_full format a80
column name format a12
column open_mode format a12
column value format a10
column profile format a24
select banner_full from v$version;
select name, open_mode from v$pdbs;
select value from v$parameter where name = 'common_user_prefix';
alter session set container = ORCLPDB1;
prompt
prompt PASSWORD_ROLLOVER_TIME rows in DBA_PROFILES (non-zero = sopuli's password_rollover capability):
select count(*) as rollover_rows from dba_profiles where resource_name = 'PASSWORD_ROLLOVER_TIME';
prompt
prompt SOPULI_* profiles created by the init wrapper:
select distinct profile from dba_profiles where profile like 'SOPULI%' order by 1;
exit
SQL

say "done"
cat <<EOF
From your machine:
  ssh -N -L 1527:127.0.0.1:1527 opc@<this VM's public IP>
then target dsn "127.0.0.1:1527/ORCLPDB1", oracle: { scope: pdb, container: ORCLPDB1 }.
Log: $LOG
EOF
