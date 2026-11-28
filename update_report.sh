#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "$0")"

branch=$(git branch --show-current)
if [[ -z "$branch" ]] ||
    ! remote=$(git config --get "branch.$branch.remote") ||
    ! upstream_ref=$(git config --get "branch.$branch.merge"); then
    printf '%s\n' 'Настройте upstream для текущей ветки Git.' >&2
    exit 1
fi

python_bin=python3
if [[ -x .venv/bin/python ]]; then
    python_bin=.venv/bin/python
elif [[ -x venv/bin/python ]]; then
    python_bin=venv/bin/python
fi

"$python_bin" main.py \
    --top 100 \
    --timeout 2.0 \
    --workers 200 \
    --max-check 30000 \
    --output-dir verified \
    --geoip data/GeoLite2-Country.mmdb \
    --skip-socks \
    --markdown-report

report_path=verified/proxy_report.md
git add -- "$report_path"
if git diff --cached --quiet -- "$report_path"; then
    printf '%s\n' 'Отчёт совпадает с последним коммитом.'
else
    updated_at=$(TZ=Europe/Moscow date '+%Y-%m-%d %H:%M:%S %z')
    git commit --only -m "Update proxy report ($updated_at)" -- "$report_path"
fi

git push "$remote" "HEAD:$upstream_ref"
