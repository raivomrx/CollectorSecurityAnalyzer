"""Fixed commands containing public locators only; never download/evaluate code."""
import hashlib
import base64
import re

PORTAL_SCRIPT = """document.querySelectorAll('[data-copy-command]').forEach(function(button){button.addEventListener('click',async function(){const code=document.getElementById(button.dataset.copyCommand);try{await navigator.clipboard.writeText(code.textContent);button.textContent='Copied';}catch(error){const range=document.createRange();range.selectNodeContents(code);const selection=window.getSelection();selection.removeAllRanges();selection.addRange(range);button.textContent='Select and copy the command above';}});});"""
PORTAL_SCRIPT_HASH = base64.b64encode(hashlib.sha256(PORTAL_SCRIPT.encode()).digest()).decode()


def quick_start_command(lab_id, envelope_id, *, quick_run=False):
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", lab_id) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", envelope_id):
        raise ValueError("CSA-TRUST-LOCATOR")
    policy = " -ExecutionPolicy Bypass" if quick_run else ""
    mode = " --quick-run" if quick_run else ""
    return ('powershell.exe -NoProfile' + policy + ' -Command "& (Join-Path '
        "([Environment]::GetFolderPath('ProgramFiles')) 'CSA\\Collector\\CSA-TrustedCollector.exe') "
        f"--lab '{lab_id}' --envelope '{envelope_id}'" + mode + '"')
