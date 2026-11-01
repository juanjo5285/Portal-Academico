#!/usr/bin/env bash
# Simulación controlada de fuga de credenciales en Git y detección con Gitleaks.
# Todas las credenciales se generan al azar en este momento: son FICTICIAS.
set -uo pipefail
DEMO=${1:-lab/demo-fuga}
OUT=${2:-docs/evidencias}
rm -rf "$DEMO" && mkdir -p "$DEMO" "$OUT"
OUT=$(cd "$OUT" && pwd)
cd "$DEMO"
git init -q -b main
git config user.email "estudiante@ejemplo.edu.gt"; git config user.name "Estudiante MASI"

rnd() { LC_ALL=C tr -dc "$1" </dev/urandom | head -c "$2"; }
AWS_ID="AKIA$(rnd 'A-Z2-7' 16)"
AWS_SECRET="$(rnd 'A-Za-z0-9' 40)"
GH_TOKEN="ghp_$(rnd 'A-Za-z0-9' 36)"

echo "== 1) Commit con credenciales escritas en el código (error del desarrollador)"
cat > config.py <<PY
# Configuración del portal (VERSIÓN INSEGURA)
AWS_ACCESS_KEY_ID = "$AWS_ID"
AWS_SECRET_ACCESS_KEY = "$AWS_SECRET"
GITHUB_TOKEN = "$GH_TOKEN"
PY
git add config.py && git commit -qm "Configuración inicial del portal"

echo "== 2) El desarrollador 'borra' el secreto en un nuevo commit"
cat > config.py <<'PY'
import os
AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
PY
git commit -qam "Mover credenciales a variables de entorno"
git log --oneline | tee "$OUT/gitleaks_00_git_log.txt"

echo "== 3) Escaneo SOLO de los archivos actuales (gitleaks dir) -> parece limpio"
gitleaks dir . --no-banner --no-color --redact -v 2>&1 | tee "$OUT/gitleaks_01_dir_actual.txt"; echo "exit=$?" >> "$OUT/gitleaks_01_dir_actual.txt"

echo "== 4) Escaneo del HISTORIAL completo (gitleaks git) -> el secreto sigue ahí"
gitleaks git . --no-banner --no-color --redact -v --report-format json --report-path "$OUT/gitleaks_02_historial.json" \
  2>&1 | tee "$OUT/gitleaks_02_historial.txt"
RC=${PIPESTATUS[0]}; echo "exit=$RC" >> "$OUT/gitleaks_02_historial.txt"

echo "== 5) Prueba de que cualquiera con el repo recupera el secreto del historial"
git show HEAD~1:config.py | sed -E 's/(= ")(.{6}).*(")/\1\2…[recortado en la evidencia]\3/' | tee "$OUT/gitleaks_03_git_show.txt"

echo "== 6) Corrección del repositorio: reescritura del historial + limpieza"
#  (paso 0, previo y obligatorio: REVOCAR/ROTAR las credenciales en AWS y GitHub)
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f --tree-filter \
  "if [ -f config.py ]; then sed -i -E 's/= \"[^\"]+\"/= os.environ.get(\"REDACTADO\")/' config.py; fi" \
  -- --all >/dev/null 2>&1
rm -rf .git/refs/original && git reflog expire --expire=now --all && git gc -q --prune=now --aggressive
gitleaks git . --no-banner --no-color --redact -v 2>&1 | tee "$OUT/gitleaks_04_tras_limpieza.txt"; echo "exit=$?" >> "$OUT/gitleaks_04_tras_limpieza.txt"
exit $RC
