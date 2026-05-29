# post_hunt.ps1 — Run after any hunt to auto-award XP to agents.
# Usage: .\post_hunt.ps1

$latest    = Get-ChildItem "$PSScriptRoot\output\secrets_*.json" |
             Sort-Object LastWriteTime -Descending |
             Select-Object -First 1

$validated = Get-ChildItem "$PSScriptRoot\output\validated_*.json" |
             Sort-Object LastWriteTime -Descending |
             Select-Object -First 1

$huntArgs = @()
if ($latest)    { $huntArgs += "--hunt-file";      $huntArgs += $latest.FullName }
if ($validated) { $huntArgs += "--validated-file"; $huntArgs += $validated.FullName }

python "C:\Users\aduad\tools\agent-leveling\hunt_xp.py" @huntArgs

python "C:\Users\aduad\tools\agent-leveling\level_up.py" --leaderboard
