@echo off
setlocal
call pwsh -ExecutionPolicy Bypass -c "Set-Alias Get-WmiObject Get-CimInstance; Import-Module %~dp0SpeculationControl\SpeculationControl.psm1; Get-SpeculationControlSettings"