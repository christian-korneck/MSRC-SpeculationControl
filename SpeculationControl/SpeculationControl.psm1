function Get-SpeculationControlSettings {
  <#

  .SYNOPSIS
  This function queries the speculation control settings for the system.

  .DESCRIPTION
  This function queries the speculation control settings for the system.

  Version 1.3.
  
  #>

  [CmdletBinding()]
  param (

  )
  
  process {

    $NtQSIDefinition = @'
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(uint systemInformationClass, IntPtr systemInformation, uint systemInformationLength, IntPtr returnLength);
'@
    
    $ntdll = Add-Type -MemberDefinition $NtQSIDefinition -Name 'ntdll' -Namespace 'Win32' -PassThru


    [System.IntPtr]$systemInformationPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
    [System.IntPtr]$returnLengthPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)

    $object = New-Object -TypeName PSObject

    try {
    
        #
        # Query branch target injection information.
        #

        Write-Host "Speculation control settings for CVE-2017-5715 [branch target injection]" -ForegroundColor Cyan
        Write-Host

        $btiHardwarePresent = $false
        $btiWindowsSupportPresent = $false
        $btiWindowsSupportEnabled = $false
        $btiDisabledBySystemPolicy = $false
        $btiDisabledByNoHardwareSupport = $false
    
        [System.UInt32]$systemInformationClass = 201
        [System.UInt32]$systemInformationLength = 4

        $retval = $ntdll::NtQuerySystemInformation($systemInformationClass, $systemInformationPtr, $systemInformationLength, $returnLengthPtr)

        if ($retval -eq 0xc0000003 -or $retval -eq 0xc0000002) {
            # fallthrough
        }
        elseif ($retval -ne 0) {
            throw (("Querying branch target injection information failed with error {0:X8}" -f $retval))
        }
        else {
    
            [System.UInt32]$scfBpbEnabled = 0x01
            [System.UInt32]$scfBpbDisabledSystemPolicy = 0x02
            [System.UInt32]$scfBpbDisabledNoHardwareSupport = 0x04
            [System.UInt32]$scfHwReg1Enumerated = 0x08
            [System.UInt32]$scfHwReg2Enumerated = 0x10
            [System.UInt32]$scfHwMode1Present = 0x20
            [System.UInt32]$scfHwMode2Present = 0x40
            [System.UInt32]$scfSmepPresent = 0x80

            [System.UInt32]$flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr)

            $btiHardwarePresent = ((($flags -band $scfHwReg1Enumerated) -ne 0) -or (($flags -band $scfHwReg2Enumerated)))
            $btiWindowsSupportPresent = $true
            $btiWindowsSupportEnabled = (($flags -band $scfBpbEnabled) -ne 0)

            if ($btiWindowsSupportEnabled -eq $false) {
                $btiDisabledBySystemPolicy = (($flags -band $scfBpbDisabledSystemPolicy) -ne 0)
                $btiDisabledByNoHardwareSupport = (($flags -band $scfBpbDisabledNoHardwareSupport) -ne 0)
            }

            if ($PSBoundParameters['Verbose']) {
                Write-Host "BpbEnabled                   :" (($flags -band $scfBpbEnabled) -ne 0)
                Write-Host "BpbDisabledSystemPolicy      :" (($flags -band $scfBpbDisabledSystemPolicy) -ne 0)
                Write-Host "BpbDisabledNoHardwareSupport :" (($flags -band $scfBpbDisabledNoHardwareSupport) -ne 0)
                Write-Host "HwReg1Enumerated             :" (($flags -band $scfHwReg1Enumerated) -ne 0)
                Write-Host "HwReg2Enumerated             :" (($flags -band $scfHwReg2Enumerated) -ne 0)
                Write-Host "HwMode1Present               :" (($flags -band $scfHwMode1Present) -ne 0)
                Write-Host "HwMode2Present               :" (($flags -band $scfHwMode2Present) -ne 0)
                Write-Host "SmepPresent                  :" (($flags -band $scfSmepPresent) -ne 0)
            }
        }

        Write-Host "Hardware support for branch target injection mitigation is present:"($btiHardwarePresent) -ForegroundColor $(If ($btiHardwarePresent) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Red })
        Write-Host "Windows OS support for branch target injection mitigation is present:"($btiWindowsSupportPresent) -ForegroundColor $(If ($btiWindowsSupportPresent) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Red })
        Write-Host "Windows OS support for branch target injection mitigation is enabled:"($btiWindowsSupportEnabled) -ForegroundColor $(If ($btiWindowsSupportEnabled) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Red })
  
        if ($btiWindowsSupportPresent -eq $true -and $btiWindowsSupportEnabled -eq $false) {
            Write-Host -ForegroundColor Red "Windows OS support for branch target injection mitigation is disabled by system policy:"($btiDisabledBySystemPolicy)
            Write-Host -ForegroundColor Red "Windows OS support for branch target injection mitigation is disabled by absence of hardware support:"($btiDisabledByNoHardwareSupport)
        }
        
        $object | Add-Member -MemberType NoteProperty -Name BTIHardwarePresent -Value $btiHardwarePresent
        $object | Add-Member -MemberType NoteProperty -Name BTIWindowsSupportPresent -Value $btiWindowsSupportPresent
        $object | Add-Member -MemberType NoteProperty -Name BTIWindowsSupportEnabled -Value $btiWindowsSupportEnabled
        $object | Add-Member -MemberType NoteProperty -Name BTIDisabledBySystemPolicy -Value $btiDisabledBySystemPolicy
        $object | Add-Member -MemberType NoteProperty -Name BTIDisabledByNoHardwareSupport -Value $btiDisabledByNoHardwareSupport

        #
        # Query kernel VA shadow information.
        #

        Write-Host
        Write-Host "Speculation control settings for CVE-2017-5754 [rogue data cache load]" -ForegroundColor Cyan
        Write-Host    

        $kvaShadowRequired = $true
        $kvaShadowPresent = $false
        $kvaShadowEnabled = $false
        $kvaShadowPcidEnabled = $false

        $cpu = Get-WmiObject Win32_Processor

        if ($cpu.Manufacturer -eq "AuthenticAMD") {
            $kvaShadowRequired = $false
        }
        elseif ($cpu.Manufacturer -eq "GenuineIntel") {
            $regex = [regex]'Family (\d+) Model (\d+) Stepping (\d+)'
            $result = $regex.Match($cpu.Description)
            
            if ($result.Success) {
                $family = [System.UInt32]$result.Groups[1].Value
                $model = [System.UInt32]$result.Groups[2].Value
                $stepping = [System.UInt32]$result.Groups[3].Value
                
                if (($family -eq 0x6) -and 
                    (($model -eq 0x1c) -or
                     ($model -eq 0x26) -or
                     ($model -eq 0x27) -or
                     ($model -eq 0x36) -or
                     ($model -eq 0x35))) {

                    $kvaShadowRequired = $false
                }
            }
        }
        else {
            throw ("Unsupported processor manufacturer: {0}" -f $cpu.Manufacturer)
        }

        [System.UInt32]$systemInformationClass = 196
        [System.UInt32]$systemInformationLength = 4

        $retval = $ntdll::NtQuerySystemInformation($systemInformationClass, $systemInformationPtr, $systemInformationLength, $returnLengthPtr)

        if ($retval -eq 0xc0000003 -or $retval -eq 0xc0000002) {
        }
        elseif ($retval -ne 0) {
            throw (("Querying kernel VA shadow information failed with error {0:X8}" -f $retval))
        }
        else {
    
            [System.UInt32]$kvaShadowEnabledFlag = 0x01
            [System.UInt32]$kvaShadowUserGlobalFlag = 0x02
            [System.UInt32]$kvaShadowPcidFlag = 0x04
            [System.UInt32]$kvaShadowInvpcidFlag = 0x08

            [System.UInt32]$flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr)

            $kvaShadowPresent = $true
            $kvaShadowEnabled = (($flags -band $kvaShadowEnabledFlag) -ne 0)
            $kvaShadowPcidEnabled = ((($flags -band $kvaShadowPcidFlag) -ne 0) -and (($flags -band $kvaShadowInvpcidFlag) -ne 0))

            if ($PSBoundParameters['Verbose']) {
                Write-Host "KvaShadowEnabled             :" (($flags -band $kvaShadowEnabledFlag) -ne 0)
                Write-Host "KvaShadowUserGlobal          :" (($flags -band $kvaShadowUserGlobalFlag) -ne 0)
                Write-Host "KvaShadowPcid                :" (($flags -band $kvaShadowPcidFlag) -ne 0)
                Write-Host "KvaShadowInvpcid             :" (($flags -band $kvaShadowInvpcidFlag) -ne 0)
            }
        }
        
        Write-Host "Hardware requires kernel VA shadowing:"$kvaShadowRequired

        if ($kvaShadowRequired) {

            Write-Host "Windows OS support for kernel VA shadow is present:"$kvaShadowPresent -ForegroundColor $(If ($kvaShadowPresent) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Red })
            Write-Host "Windows OS support for kernel VA shadow is enabled:"$kvaShadowEnabled -ForegroundColor $(If ($kvaShadowEnabled) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Red })

            if ($kvaShadowEnabled) {
                Write-Host "Windows OS support for PCID performance optimization is enabled: $kvaShadowPcidEnabled [not required for security]" -ForegroundColor $(If ($kvaShadowPcidEnabled) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Blue })
            }
        }

        
        $object | Add-Member -MemberType NoteProperty -Name KVAShadowRequired -Value $kvaShadowRequired
        $object | Add-Member -MemberType NoteProperty -Name KVAShadowWindowsSupportPresent -Value $kvaShadowPresent
        $object | Add-Member -MemberType NoteProperty -Name KVAShadowWindowsSupportEnabled -Value $kvaShadowEnabled
        $object | Add-Member -MemberType NoteProperty -Name KVAShadowPcidEnabled -Value $kvaShadowPcidEnabled

        #
        # Provide guidance as appropriate.
        #

        $actions = @()
        
        if ($btiHardwarePresent -eq $false) {
            $actions += "Install BIOS/firmware update provided by your device OEM that enables hardware support for the branch target injection mitigation."
        }

        if ($btiWindowsSupportPresent -eq $false -or $kvaShadowPresent -eq $false) {
            $actions += "Install the latest available updates for Windows with support for speculation control mitigations."
        }

        if (($btiHardwarePresent -eq $true -and $btiWindowsSupportEnabled -eq $false) -or ($kvaShadowRequired -eq $true -and $kvaShadowEnabled -eq $false)) {
            $guidanceUri = ""
            $guidanceType = ""

            
            $os = Get-WmiObject Win32_OperatingSystem

            if ($os.ProductType -eq 1) {
                # Workstation
                $guidanceUri = "https://support.microsoft.com/help/4073119"
                $guidanceType = "Client"
            }
            else {
                # Server/DC
                $guidanceUri = "https://support.microsoft.com/help/4072698"
                $guidanceType = "Server"
            }

            $actions += "Follow the guidance for enabling Windows $guidanceType support for speculation control mitigations described in $guidanceUri"
        }

        if ($actions.Length -gt 0) {

            Write-Host
            Write-Host "Suggested actions" -ForegroundColor Cyan
            Write-Host 

            foreach ($action in $actions) {
                Write-Host " *" $action
            }
        }


        return $object

    }
    finally
    {
        if ($systemInformationPtr -ne [System.IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($systemInformationPtr)
        }
 
        if ($returnLengthPtr -ne [System.IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($returnLengthPtr)
        }
    }    
  }
}
# SIG # Begin signature block
# MIIarwYJKoZIhvcNAQcCoIIaoDCCGpwCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUBPjPvVyQFqZQ9qL6+kNgWEVn
# lOagghWCMIIEwjCCA6qgAwIBAgITMwAAALm8D05X42ZlOAAAAAAAuTANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTYwOTA3MTc1ODQ2
# WhcNMTgwOTA3MTc1ODQ2WjCBsjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEMMAoGA1UECxMDQU9DMScwJQYDVQQLEx5uQ2lwaGVyIERTRSBFU046
# NkJGNi0yRDUyLTkyQzExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNl
# cnZpY2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdXDM6Nw8Ck6Kk
# 8k7KXa6ef90VvfETAqgHmtlBZbMr2580HCnjeUqVnMptYOf4SPDNDhtJ7Qc3PCk6
# GJ6J/fssnK9n/3QVnAmIBSINx6vUOasQIBIvf72aGP3Ax0OMx003HDcenhkn5+YJ
# 3IEMJMGN9AvoxZpNvvP2daLhVCLhtrvyPI4ZbWTmilwNQdI7KG6UQsEcVw9h+H/e
# QK3GUHpgjkAQIgLlxdl2GUzuyRB7w3q8IcL2knoiXyaJnu/8ZImBAUz/e9Y0hceH
# XSyLwm3yD7cTI/1NIoC3NCa4JNC0mIL34IiPmpxOsrYrnC8N56eB3RaqVTgpP0GT
# A/rYkXHBAgMBAAGjggEJMIIBBTAdBgNVHQ4EFgQUEDX8qfRQm15YRy1KztfgtxHB
# HfkwHwYDVR0jBBgwFoAUIzT42VJGcArtQPt2+7MrsMM1sw8wVAYDVR0fBE0wSzBJ
# oEegRYZDaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMv
# TWljcm9zb2Z0VGltZVN0YW1wUENBLmNybDBYBggrBgEFBQcBAQRMMEowSAYIKwYB
# BQUHMAKGPGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljcm9z
# b2Z0VGltZVN0YW1wUENBLmNydDATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQUFAAOCAQEAUYrMwJvGAcCAGnvYWKAiGHo5ee703br1cOLmeU48bNWanQyV
# B5F+9NduGCCYR+Dy/c6Qz0AAHOrfKZRMm9XVZjzR0SURkrw0XgUG+lUacr+buJk9
# soiQVq1JRSFVyzsjNTgUWRVHhIvvP9DYGG8ErZbn0b9CG4fkrmnP+K23Wdoz6PM1
# jzmLO50vGvU6WlBIVdDggAoWW4o8aomMZRdgmGxKPcNAVRVd6pvZz73GnTePE0Su
# d3zOUPMLoHd+DrNbb3tOwJhCCEIs2OMvQyZ7A6sS/YlTseBH5YefOj87+ZliRZCv
# hZJ/QldmfA3RI5Is2IKz45m0pmXUM9snjK0p6TCCBO0wggPVoAMCAQICEzMAAAF5
# fC5XTlLhytYAAQAAAXkwDQYJKoZIhvcNAQEFBQAweTELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEjMCEGA1UEAxMaTWljcm9zb2Z0IENvZGUgU2ln
# bmluZyBQQ0EwHhcNMTcwODExMjAxMTE1WhcNMTgwODExMjAxMTE1WjCBgzELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjENMAsGA1UECxMETU9QUjEe
# MBwGA1UEAxMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMIIBIjANBgkqhkiG9w0BAQEF
# AAOCAQ8AMIIBCgKCAQEAqCn+1BDI/1UKnpkAA1KP3LC/+av4Uf5cjFTCJ85MK5br
# 24Ecy4Yrecp1frhngyaGvdYvHD7HWKqPb5X7WvynxhvBw+hMF04iPbdbVlx/11r1
# Lbq7pgm/BnzumP5A+TC4a/5Ab3SzuNY4ScnQhwcvMd+2vE6j0J63YntWcHVPZ78F
# zKOuvgCSwhtQoWE7EAABsYbQKfNA9Q/Zow9Xq2MJqNypaudHQ6e+FcQ9J6ToVlKI
# z1mZoQCENpvQOdIqDS/mBOK/E5aIg6lRNxhBieL5hZ2OZRo9A2TMxd5QcF3yC4Wp
# j7FF6Hf/g50Ju3Lg5lYIlbkrgxKJMfznWHIdvfmDIwIDAQABo4IBYTCCAV0wEwYD
# VR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFPjkfo0cY3wAqsxzAErT8m04qs2B
# MFIGA1UdEQRLMEmkRzBFMQ0wCwYDVQQLEwRNT1BSMTQwMgYDVQQFEysyMjk4MDMr
# MWFiZjllNWYtY2VkMC00MmU2LWE2NWQtZDkzNTA5NTlmZTBlMB8GA1UdIwQYMBaA
# FMsR6MrStBZYAck3LjMWFrlMmgofMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY0NvZFNpZ1BDQV8w
# OC0zMS0yMDEwLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljQ29kU2lnUENBXzA4LTMx
# LTIwMTAuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQBvS2t+hg3YCyZQazqIyFqp9rLq
# Kpmn5QY0RAHvc/utL/3t+NWAajUcNMcTDLVeZDxza4zyb9Npvs47D5v5BXI8HUbh
# 6Jw+NrFvNammUFR/4dRXPTseelyPAT93P15zJ1f6pzDn1HKvi99xIv2K4PrgLd9f
# 8t53ZN/asAYACatGkKP1/oGGLJMrdcYRKNfliuIcJ6uXjJrE4gcZ0/JkF7Er3fMI
# enhQhQYyHDlQo82LcN4I1XtvTD+a6HVt5MsTVxwpWThfvkWrpprK+SmezTjPucgF
# uiz7xCW/aA3fD3tCGpXHj71aa5ALUfrXt+ePsrMzKHMDXH+jRoKcrbY2d3aHMIIF
# vDCCA6SgAwIBAgIKYTMmGgAAAAAAMTANBgkqhkiG9w0BAQUFADBfMRMwEQYKCZIm
# iZPyLGQBGRYDY29tMRkwFwYKCZImiZPyLGQBGRYJbWljcm9zb2Z0MS0wKwYDVQQD
# EyRNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTAwODMx
# MjIxOTMyWhcNMjAwODMxMjIyOTMyWjB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBD
# QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJyWVwZMGS/HZpgICBC
# mXZTbD4b1m/My/Hqa/6XFhDg3zp0gxq3L6Ay7P/ewkJOI9VyANs1VwqJyq4gSfTw
# aKxNS42lvXlLcZtHB9r9Jd+ddYjPqnNEf9eB2/O98jakyVxF3K+tPeAoaJcap6Vy
# c1bxF5Tk/TWUcqDWdl8ed0WDhTgW0HNbBbpnUo2lsmkv2hkL/pJ0KeJ2L1TdFDBZ
# +NKNYv3LyV9GMVC5JxPkQDDPcikQKCLHN049oDI9kM2hOAaFXE5WgigqBTK3S9dP
# Y+fSLWLxRT3nrAgA9kahntFbjCZT6HqqSvJGzzc8OJ60d1ylF56NyxGPVjzBrAlf
# A9MCAwEAAaOCAV4wggFaMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFMsR6MrS
# tBZYAck3LjMWFrlMmgofMAsGA1UdDwQEAwIBhjASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBT90TFO0yaKleGYYDuoMW+mPLzYLTAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTAfBgNVHSMEGDAWgBQOrIJgQFYnl+UlE/wq4QpTlVnk
# pDBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9taWNyb3NvZnRyb290Y2VydC5jcmwwVAYIKwYBBQUHAQEE
# SDBGMEQGCCsGAQUFBzAChjhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY3Jvc29mdFJvb3RDZXJ0LmNydDANBgkqhkiG9w0BAQUFAAOCAgEAWTk+
# fyZGr+tvQLEytWrrDi9uqEn361917Uw7LddDrQv+y+ktMaMjzHxQmIAhXaw9L0y6
# oqhWnONwu7i0+Hm1SXL3PupBf8rhDBdpy6WcIC36C1DEVs0t40rSvHDnqA2iA6VW
# 4LiKS1fylUKc8fPv7uOGHzQ8uFaa8FMjhSqkghyT4pQHHfLiTviMocroE6WRTsgb
# 0o9ylSpxbZsa+BzwU9ZnzCL/XB3Nooy9J7J5Y1ZEolHN+emjWFbdmwJFRC9f9Nqu
# 1IIybvyklRPk62nnqaIsvsgrEA5ljpnb9aL6EiYJZTiU8XofSrvR4Vbo0HiWGFzJ
# NRZf3ZMdSY4tvq00RBzuEBUaAF3dNVshzpjHCe6FDoxPbQ4TTj18KUicctHzbMrB
# 7HCjV5JXfZSNoBtIA1r3z6NnCnSlNu0tLxfI5nI3EvRvsTxngvlSso0zFmUeDord
# EN5k9G/ORtTTF+l5xAS00/ss3x+KnqwK+xMnQK3k+eGpf0a7B2BHZWBATrBC7E7t
# s3Z52Ao0CW0cgDEf4g5U3eWh++VHEK1kmP9QFi58vwUheuKVQSdpw5OPlcmN2Jsh
# rg1cnPCiroZogwxqLbt2awAdlq3yFnv2FoMkuYjPaqhHMS+a3ONxPdcAfmJH0c6I
# ybgY+g5yjcGjPa8CQGr/aZuW4hCoELQ3UAjWwz0wggYHMIID76ADAgECAgphFmg0
# AAAAAAAcMA0GCSqGSIb3DQEBBQUAMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAX
# BgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0wNzA0MDMxMjUzMDlaFw0yMTA0MDMx
# MzAzMDlaMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAf
# BgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAJ+hbLHf20iSKnxrLhnhveLjxZlRI1Ctzt0YTiQP7tGn
# 0UytdDAgEesH1VSVFUmUG0KSrphcMCbaAGvoe73siQcP9w4EmPCJzB/LMySHnfL0
# Zxws/HvniB3q506jocEjU8qN+kXPCdBer9CwQgSi+aZsk2fXKNxGU7CG0OUoRi4n
# rIZPVVIM5AMs+2qQkDBuh/NZMJ36ftaXs+ghl3740hPzCLdTbVK0RZCfSABKR2YR
# JylmqJfk0waBSqL5hKcRRxQJgp+E7VV4/gGaHVAIhQAQMEbtt94jRrvELVSfrx54
# QTF3zJvfO4OToWECtR0Nsfz3m7IBziJLVP/5BcPCIAsCAwEAAaOCAaswggGnMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFCM0+NlSRnAK7UD7dvuzK7DDNbMPMAsG
# A1UdDwQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADCBmAYDVR0jBIGQMIGNgBQOrIJg
# QFYnl+UlE/wq4QpTlVnkpKFjpGEwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcG
# CgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5ghB5rRahSqClrUxzWPQHEy5lMFAGA1UdHwRJ
# MEcwRaBDoEGGP2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL21pY3Jvc29mdHJvb3RjZXJ0LmNybDBUBggrBgEFBQcBAQRIMEYwRAYIKwYB
# BQUHMAKGOGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljcm9z
# b2Z0Um9vdENlcnQuY3J0MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEB
# BQUAA4ICAQAQl4rDXANENt3ptK132855UU0BsS50cVttDBOrzr57j7gu1BKijG1i
# uFcCy04gE1CZ3XpA4le7r1iaHOEdAYasu3jyi9DsOwHu4r6PCgXIjUji8FMV3U+r
# kuTnjWrVgMHmlPIGL4UD6ZEqJCJw+/b85HiZLg33B+JwvBhOnY5rCnKVuKE5nGct
# xVEO6mJcPxaYiyA/4gcaMvnMMUp2MT0rcgvI6nA9/4UKE9/CCmGO8Ne4F+tOi3/F
# NSteo7/rvH0LQnvUU3Ih7jDKu3hlXFsBFwoUDtLaFJj1PLlmWLMtL+f5hYbMUVbo
# nXCUbKw5TNT2eb+qGHpiKe+imyk0BncaYsk9Hm0fgvALxyy7z0Oz5fnsfbXjpKh0
# NbhOxXEjEiZ2CzxSjHFaRkMUvLOzsE1nyJ9C/4B5IYCeFTBm6EISXhrIniIh0EPp
# K+m79EjMLNTYMoBMJipIJF9a6lbvpt6Znco6b72BJ3QGEe52Ib+bgsEnVLaxaj2J
# oXZhtG6hE6a/qkfwEm/9ijJssv7fUciMI8lmvZ0dhxJkAj0tr1mPuOQh5bWwymO0
# eFQF1EEuUKyUsKV4q7OglnUa2ZKHE3UiLzKoCG6gW4wlv6DvhMoh1useT8ma7kng
# 9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TGCBJcwggST
# AgEBMIGQMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xIzAh
# BgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBAhMzAAABeXwuV05S4crW
# AAEAAAF5MAkGBSsOAwIaBQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOnE
# GawONngpoawv6Sk6BGKlFKcOMFAGCisGAQQBgjcCAQwxQjBAoBaAFABQAG8AdwBl
# AHIAUwBoAGUAbABsoSaAJGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9Qb3dlclNo
# ZWxsIDANBgkqhkiG9w0BAQEFAASCAQCOUcNUopDwbjz30tvBcXc1RXGj5U9HFqOo
# YDS5Mz5LtDl+/KsRfwD7ktK8n23+rLe7DFAF1Lu26PDJ93cZBZ+EXcAIi5YFL0K6
# hOkOSuWDBR1qpJudcKi70AYa1dHskQJI4rITCr6StI4viMT2yLOcPTEy842KFDOK
# A1my7yyQCFpHdyooS5tpvudx7TAMUeogBPybBp8YMpm/RayTApuFLwfvfEa6Ekk0
# OkH5b2tgnHRpRoI/ytduXVA5bdmdhle0Wq4yMBaQ4LcT2mYA+BJDah/AFIemok9b
# 39CXBtc7AG/NkGzC4hEhKzI4RUtP6/0sl8VHryBwr/WRGCFgI2x7oYICKDCCAiQG
# CSqGSIb3DQEJBjGCAhUwggIRAgEBMIGOMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xITAfBgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QQITMwAAALm8D05X42ZlOAAAAAAAuTAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTgwMTA1MTk0NjMxWjAjBgkq
# hkiG9w0BCQQxFgQUttZeuwmNEzkcIoWio5tcO8OApd4wDQYJKoZIhvcNAQEFBQAE
# ggEAPB166O25JvdBVE3RGR9Qx+WjSSx+wxHQlBEu9Qf3IwBbwBRRq6HHpbAQdOE4
# kqgl/eKYCr7WcYeBwWGN+/7n9Q/gATUfJCH14cTswq2d7skYyywJ/Jun9K6bFY/U
# mSQ6O7pJh85ChsnY7aLy4tbl23gAW8TxXIfPK/s9ICeSa9TKgCd7kHAP5+ll1wWi
# SWu2257rWQcNLwZpFhgVurIlOfLxgb4vHWOXx3W0oTl+47/bgblq9eBvtgMaMpXF
# 0R4BDAhOJe9qzzQV4BDBmeAF41+5+WPNC/P9/ssXeOx+fHM4M3WPm82UkzeMPcP5
# GbUi47sCu1KGccNjh1mbU9iBQQ==
# SIG # End signature block
