param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8766
)

$ErrorActionPreference = 'Stop'
$pythonCommand = $null
$pythonPrefix = @()
$candidates = @(
    @{ Name = 'py'; Prefix = @('-3') },
    @{ Name = 'python'; Prefix = @() },
    @{ Name = 'python3'; Prefix = @() }
)

foreach ($candidate in $candidates) {
    $command = Get-Command $candidate.Name -ErrorAction SilentlyContinue
    if ($null -eq $command) { continue }
    $candidatePrefix = $candidate.Prefix
    try {
        & $command.Source @candidatePrefix -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' *> $null
        if ($LASTEXITCODE -eq 0) {
            $pythonCommand = $command.Source
            $pythonPrefix = $candidatePrefix
            break
        }
    } catch {
        continue
    }
}

if ($null -eq $pythonCommand) {
    throw 'Python 3.10 or newer was not found. Install Python or run the documented module command with an existing Python interpreter.'
}

$runExitCode = 1
Push-Location -LiteralPath $PSScriptRoot
try {
    Write-Host "RestoreGuard local reference prototype: http://127.0.0.1:$Port"
    Write-Host 'Open the address in your browser. Press Ctrl+C here to stop the server.'
    & $pythonCommand @pythonPrefix -m restoreguard serve --port $Port --runs-dir runs
    $runExitCode = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $runExitCode
