param([ValidateSet('baseline','retest','current')][string]$Phase='current', [string]$Lab=(Join-Path $PSScriptRoot '../../it-support-homelab'))
$ErrorActionPreference = 'Stop'
python (Join-Path $PSScriptRoot 'assess.py') --lab $Lab --phase $Phase
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
