param([string]$Binary = "target/debug/custos.exe")
$ErrorActionPreference = "Stop"
$exe = (Resolve-Path $Binary).Path
$name = "CustosRegression-$PID"
$directory = Join-Path $env:TEMP ([guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $directory | Out-Null
$config = Join-Path $directory "config.toml"
$decisions = Join-Path $directory "decisions.jsonl"
@"
[daemon]
bouncer_listen = "127.0.0.1:0"
decisions_file = '$decisions'
[firewall]
enabled = false
"@ | Set-Content -Path $config -Encoding utf8NoBOM
$registered = $false
try {
    # This temporary service never enables a firewall or calls an external API.
    $command = "`"$exe`" --windows-service --config `"$config`" run --mock-jev"
    & sc.exe create $name "binPath=" $command "start=" "demand"
    if ($LASTEXITCODE -ne 0) { throw "Could not register temporary SCM smoke-test service" }
    $registered = $true
    Start-Service $name
    $service = Get-Service $name
    $service.WaitForStatus("Running", [timespan]::FromSeconds(20))
    Start-Sleep -Seconds 2
    if ((Get-Service $name).Status -ne "Running") { throw "SCM process exited after startup" }
    Stop-Service $name
    (Get-Service $name).WaitForStatus("Stopped", [timespan]::FromSeconds(30))
} finally {
    if ($registered) {
        Stop-Service $name -ErrorAction SilentlyContinue
        & sc.exe delete $name
    }
    Remove-Item -Recurse -Force $directory
}
