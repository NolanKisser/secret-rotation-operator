#!/usr/bin/env bash
# End-to-end test: build the image, deploy into a fresh kind cluster, and
# assert a full rotation lifecycle against real kubelet/controllers (including
# garbage collection and rolling restarts, which envtest does not run).
set -euo pipefail

KIND_CLUSTER="${KIND_CLUSTER:-secret-rotation}"
IMG="${IMG:-secret-rotation-operator:e2e}"
NS=e2e
OPERATOR_NS=secret-rotation-system

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31mFAIL: %s\033[0m\n' "$*"; dump; exit 1; }
dump() {
  kubectl -n "$OPERATOR_NS" logs -l control-plane=controller-manager --tail=100 --prefix || true
  kubectl -n "$NS" get secretrotation,secret,deploy -o wide || true
}
wait_for() { # wait_for <description> <timeout-seconds> <command...>
  local desc=$1 timeout=$2; shift 2
  for _ in $(seq "$timeout"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  fail "timed out waiting for $desc"
}
secret_version() {
  kubectl -n "$NS" get secret demo-credentials -o jsonpath='{.metadata.annotations.rotation\.nolankisser\.github\.io/version}'
}

if ! kind get clusters | grep -qx "$KIND_CLUSTER"; then
  log "Creating kind cluster $KIND_CLUSTER"
  kind create cluster --name "$KIND_CLUSTER" --wait 120s
fi
kubectl config use-context "kind-$KIND_CLUSTER"

log "Building and loading $IMG"
docker build -t "$IMG" .
kind load docker-image "$IMG" --name "$KIND_CLUSTER"

log "Deploying operator"
make deploy IMG="$IMG"
kubectl -n "$OPERATOR_NS" rollout status deploy/secret-rotation-controller-manager --timeout=120s

log "Applying demo workload"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" apply -f config/samples/demo.yaml

wait_for "secret creation" 60 kubectl -n "$NS" get secret demo-credentials
[[ "$(secret_version)" == "1" ]] || fail "expected version 1, got $(secret_version)"
wait_for "Ready condition" 60 kubectl -n "$NS" wait secretrotation/demo --for=condition=Ready --timeout=1s

log "Checking workload was rolled for version 1"
wait_for "restart annotation" 60 bash -c \
  "kubectl -n $NS get deploy demo-app -o jsonpath='{.spec.template.metadata.annotations}' | grep -q 'demo/v1'"
kubectl -n "$NS" rollout status deploy/demo-app --timeout=120s

log "Triggering manual rotation"
before=$(kubectl -n "$NS" get secret demo-credentials -o jsonpath='{.data.password}')
kubectl -n "$NS" annotate secretrotation demo rotation.nolankisser.github.io/rotate-now="$(date +%s)" --overwrite
wait_for "version 2" 30 bash -c "[[ \$(kubectl -n $NS get secret demo-credentials -o jsonpath='{.metadata.annotations.rotation\.nolankisser\.github\.io/version}') == 2 ]]"
after=$(kubectl -n "$NS" get secret demo-credentials -o jsonpath='{.data.password}')
previous=$(kubectl -n "$NS" get secret demo-credentials -o jsonpath='{.data.password\.previous}')
[[ "$before" != "$after" ]] || fail "password did not change"
[[ "$before" == "$previous" ]] || fail "password.previous does not hold the old value"

log "Checking self-healing after external deletion"
kubectl -n "$NS" delete secret demo-credentials
# The version must keep increasing (not restart at 1), otherwise the
# workload's restart marker already matches and the rollout is skipped.
wait_for "secret recreated as version 3" 30 bash -c "[[ \$(kubectl -n $NS get secret demo-credentials -o jsonpath='{.metadata.annotations.rotation\.nolankisser\.github\.io/version}') == 3 ]]"
wait_for "workload rolled for version 3" 30 bash -c \
  "kubectl -n $NS get deploy demo-app -o jsonpath='{.spec.template.metadata.annotations}' | grep 'demo/v3' >/dev/null"

log "Checking garbage collection on delete"
kubectl -n "$NS" delete secretrotation demo --wait=true --timeout=60s
wait_for "secret garbage collected" 60 bash -c "! kubectl -n $NS get secret demo-credentials"

log "Checking rotation was logged"
# Two replicas: read every pod, since only the leader reconciles. Capture
# first instead of piping into `grep -q`: with pipefail, grep exiting early
# SIGPIPEs kubectl and fails the pipeline even when the line matched.
operator_logs=$(kubectl -n "$OPERATOR_NS" logs -l control-plane=controller-manager --tail=-1)
grep -q '"rotated secret"' <<<"$operator_logs" || fail "no rotation log lines"
if grep -q 'forbidden' <<<"$operator_logs"; then
  grep 'forbidden' <<<"$operator_logs" | head -5
  fail "operator hit RBAC denials"
fi

printf '\n\033[1;32mE2E PASSED\033[0m\n'
