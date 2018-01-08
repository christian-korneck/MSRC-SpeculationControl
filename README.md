MSRC PowerShell SpeculationControl module
=========================================

## Description

Fork of the Microsoft Security Response Center (MSRC) provided PowerShell module `SpeculationControl` from the Powershell Gallery https://www.powershellgallery.com/packages/SpeculationControl with minor changes that I needed to run it in my environment.

This module provides the ability to query the CPU speculation control settings for the system (displays if `spectre`, `meltdown` mitigations are active)

## wrapper scripts
For simple execution of the actual script, I've added a batch wrapper script:
- `Get-SpeculationControlSettings.cmd` (uses Windows Powershell, tested with PS2 (Win7) and PS5 (Win7, Win10))
- `pwsh6_Get-SpeculationControlSettings.cmd` (uses Powershell 6 Core, expects `pwsh.exe` to be found in `PATH`)

## Docs
* https://support.microsoft.com/en-us/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution

## Source / Credits / Docs
* https://www.powershellgallery.com/packages/SpeculationControl
* https://gallery.technet.microsoft.com/scriptcenter/Speculation-Control-e36f0050
* [@msftsecurity](https://twitter.com/msftsecurity)
