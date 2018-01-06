@echo off
setlocal
powershell -ExecutionPolicy Bypass -c "Import-Module %~dp0SpeculationControl\SpeculationControl.psm1; Get-SpeculationControlSettings"