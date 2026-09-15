#Requires -Version 5.1
param([string]$SignTool='', [string]$Thumbprint='')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\scripts\WindowsUsbSigningExchange.ps1')
$scratch=Join-Path ([IO.Path]::GetTempPath()) ('edr-file-exchange-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$script:checks=0
function Reject([scriptblock]$Action) {
    $failed=$false
    try { & $Action | Out-Null } catch { $failed=$true }
    if(-not $failed){throw 'Expected contract rejection did not occur'}
    $script:checks++
}
try {
    $commit='a'*40; $thumb='B'*40
    $file=Join-Path $scratch 'artifact-manifest.json'
    [IO.File]::WriteAllText($file,'{"test_only":true}')
    $request=Join-Path $scratch 'request'
    New-SigningRequest $request manifest $commit '1.2.3' arm64 @($file)
    $null=Read-SigningRequest $request manifest $commit '1.2.3' arm64; $script:checks++
    Reject { Read-SigningRequest $request manifest ('b'*40) '1.2.3' arm64 }
    Reject { Read-SigningRequest $request native $commit '1.2.3' arm64 }
    Reject { Read-SigningRequest $request manifest $commit '1.2.4' arm64 }
    Reject { Read-SigningRequest $request manifest $commit '1.2.3' amd64 }
    Reject { Get-ExchangeFile $request '../secret.exe' }
    Reject { Get-ExchangeFile $request 'bad.exe:stream' }
    Reject { New-SigningRequest $request manifest $commit '1.2.3' arm64 @($file) }
    $extra=Join-Path $request 'whole-bundle.zip'
    [IO.File]::WriteAllText($extra,'unexpected')
    Reject { Read-SigningRequest $request manifest $commit '1.2.3' arm64 }
    Remove-Item -LiteralPath $extra
    $copy=Join-Path $request 'artifact-manifest.json'
    [IO.File]::WriteAllText($copy,'{"test_only":false}')
    Reject { Read-SigningRequest $request manifest $commit '1.2.3' arm64 }
    Copy-Item -LiteralPath $file -Destination $copy -Force
    $manifest=Get-Content (Join-Path $request 'request.json') -Raw | ConvertFrom-Json
    $manifest.files=@($manifest.files)+@($manifest.files)
    Write-ExchangeJson (Join-Path $request 'request.json') $manifest
    Reject { Read-SigningRequest $request manifest $commit '1.2.3' arm64 }

    # Both supported native inventories must work on both architectures.
    # Optional means absent is allowed, never that an included file is unchecked.
    $required=@('FDSensor.exe','FDSecurityInstallerWorker.exe','uninstall.exe','forensic_collector_builtin.exe','FDSecuritySetupUI.exe')
    $nativeInputs=Join-Path $scratch 'native-inputs'
    New-Item -ItemType Directory -Path $nativeInputs | Out-Null
    foreach($name in ($required+@('forensic_collector.exe'))) {
        [IO.File]::WriteAllText((Join-Path $nativeInputs $name),'inventory-test-only')
    }
    foreach($arch in @('amd64','arm64')) {
        foreach($includeCollector in @($false,$true)) {
            $names=@($required)
            if($includeCollector){$names+='forensic_collector.exe'}
            $nativeRequest=Join-Path $scratch "native-$arch-$includeCollector"
            New-SigningRequest $nativeRequest native $commit '1.2.3' $arch @($names | ForEach-Object {Join-Path $nativeInputs $_})
            $r=Read-SigningRequest $nativeRequest native $commit '1.2.3' $arch
            if(@($r.files).Count -ne $names.Count){throw 'Native inventory lost files'}
            $script:checks++
            foreach($missing in $required) {
                $r.files=@($r.files | Where-Object name -cne $missing)
                Write-ExchangeJson (Join-Path $nativeRequest 'request.json') $r
                # Remove the file as well: a clean but incomplete inventory must fail.
                Remove-Item -LiteralPath (Join-Path $nativeRequest $missing)
                Reject { Read-SigningRequest $nativeRequest native $commit '1.2.3' $arch }
                Copy-Item -LiteralPath (Join-Path $nativeInputs $missing) -Destination $nativeRequest
                $r.files=@($names | ForEach-Object {
                    $p=Join-Path $nativeRequest $_
                    [pscustomobject]@{name=$_;sha256=(Get-ExchangeHash $p);size=(Get-Item $p).Length}
                })
                Write-ExchangeJson (Join-Path $nativeRequest 'request.json') $r
            }
            $extra=Join-Path $nativeRequest 'whole-bundle.zip'
            [IO.File]::WriteAllText($extra,'not allowed')
            Reject { Read-SigningRequest $nativeRequest native $commit '1.2.3' $arch }
            Remove-Item -LiteralPath $extra
            if($includeCollector) {
                $optional=Join-Path $nativeRequest 'forensic_collector.exe'
                [IO.File]::WriteAllText($optional,'tampered')
                Reject { Read-SigningRequest $nativeRequest native $commit '1.2.3' $arch }
                Remove-Item -LiteralPath $optional
                Reject { Read-SigningRequest $nativeRequest native $commit '1.2.3' $arch }
            } else {
                Copy-Item -LiteralPath (Join-Path $nativeInputs 'forensic_collector.exe') -Destination $nativeRequest
                Reject { Read-SigningRequest $nativeRequest native $commit '1.2.3' $arch }
            }
        }
    }

    # Isolate Authenticode trust lookup while exercising byte-level replacement
    # protection. Real Windows SignTool/CMS coverage lives in store-signing test.
    function Get-AuthenticodeSignature { param($LiteralPath)
        [pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Thumbprint=$thumb};TimeStamperCertificate=$true}
    }
    [byte[]]$original=New-Object byte[] 512
    [BitConverter]::GetBytes([int]128).CopyTo($original,60)
    [BitConverter]::GetBytes([uint32]0x4550).CopyTo($original,128)
    [BitConverter]::GetBytes([uint16]0x20b).CopyTo($original,152)
    $original[400]=42
    [byte[]]$signed=New-Object byte[] 528; $original.CopyTo($signed,0)
    [BitConverter]::GetBytes([uint32]512).CopyTo($signed,296)
    [BitConverter]::GetBytes([uint32]16).CopyTo($signed,300)
    $signed[216]=7
    $a=Join-Path $scratch 'original.exe'; $b=Join-Path $scratch 'signed.exe'
    [IO.File]::WriteAllBytes($a,$original); [IO.File]::WriteAllBytes($b,$signed)
    Assert-SignedExecutable $a $b $thumb; $script:checks++
    Reject { Assert-SignedExecutable $a $b ('C'*40) }
    $signed[400]=43; [IO.File]::WriteAllBytes($b,$signed)
    Reject { Assert-SignedExecutable $a $b $thumb }
    $signed[400]=42; [BitConverter]::GetBytes([uint32]32).CopyTo($signed,300)
    [IO.File]::WriteAllBytes($b,$signed)
    Reject { Assert-SignedExecutable $a $b $thumb }
    # Exercise the real hosted Installer stage with a stub only at the external
    # Inno compiler boundary. The private signing repo intentionally has no packager.
    $packager=Join-Path $PSScriptRoot '..\scripts\Complete-WindowsUsbRelease.ps1'
    if(Test-Path -LiteralPath $packager) {
        [BitConverter]::GetBytes([uint32]16).CopyTo($signed,300)
        foreach($includeCollector in @($false,$true)) {
            $hosted=Join-Path $scratch "hosted-$includeCollector"
            $runtime=Join-Path $hosted 'runtime'; $ui=Join-Path $hosted 'ui'
            $buildRoot=Join-Path $hosted 'source\install\windows-inno'
            $response=Join-Path $hosted 'response'
            New-Item -ItemType Directory -Force -Path "$runtime\collector",$ui,"$hosted\dist","$buildRoot\Output",$response | Out-Null
            $names=@($required)
            if($includeCollector){$names+='forensic_collector.exe'}
            foreach($name in $names) {
                [IO.File]::WriteAllBytes((Join-Path $nativeInputs $name),$original)
                [IO.File]::WriteAllBytes((Join-Path $response $name),$signed)
            }
            $request=Join-Path $hosted 'native-request'
            New-SigningRequest $request native $commit '1.2.3' arm64 @($names | ForEach-Object {Join-Path $nativeInputs $_})
            Write-ExchangeJson (Join-Path $response 'receipt.json') ([ordered]@{request_sha256=(Get-ExchangeHash (Join-Path $request 'request.json'));publisher=$thumb})
            Write-ExchangeJson (Join-Path $hosted 'state.json') ([ordered]@{stage='native';source_commit=$commit;version='1.2.3';architecture='arm64'})
            Write-ExchangeJson (Join-Path $hosted 'original-manifest.json') @{}
            $entries=@($names | Where-Object {$_ -ne 'FDSecuritySetupUI.exe'} | ForEach-Object {
                $relative=if($_ -like 'forensic_*'){"collector/$_"}else{$_}
                [pscustomobject]@{name=$relative;sha256='pending'}
            })
            Write-ExchangeJson (Join-Path $runtime 'native-package-integrity.json') ([ordered]@{schema='edr.windows.native-package-integrity.v1';files=$entries})
            [IO.File]::WriteAllText((Join-Path $runtime 'edr_agent_setup.exe'),'old fixture installer')
            [IO.File]::WriteAllText((Join-Path $buildRoot 'Build-BundledInstaller.ps1'), '[IO.File]::WriteAllText((Join-Path $PSScriptRoot "Output\FDSecuritySetup-bundled.exe"),"test compiler output"); $global:LASTEXITCODE=0')
            Write-ExchangeJson (Join-Path $ui 'setup-ui-manifest.json') ([ordered]@{
                version='1.2.3';target_arch='arm64';setup_target_arch='arm64';agent_binary_sha256='';runtime_identity_sha256='';publisher_thumbprint='';setup_exe_sha256='';ui_exe_sha256='';setup_exe_signed=$false;ui_exe_signed=$false;capabilities=@{signature_status='unsigned'};generated_at_utc=''
            })
            # Reproduce upload/download: empty directories do not survive artifacts.
            Remove-Item -LiteralPath (Join-Path $hosted 'dist')
            & $packager -Stage Installer -OutputDirectory $hosted -ExpectedCommit $commit -Thumbprint $thumb -ManifestSignerSubject 'CN=Fixture' -ResponseDirectory $response
            $state=Get-Content (Join-Path $hosted 'state.json') -Raw | ConvertFrom-Json
            if($state.stage -ne 'installer'){throw 'Hosted installer did not advance'}
            if((Test-Path "$runtime\collector\forensic_collector.exe") -ne $includeCollector){throw 'Optional collector presence changed'}
            foreach($name in $names | Where-Object {$_ -like 'forensic_*'}) {
                if((Get-ExchangeHash "$runtime\collector\$name") -cne (Get-ExchangeHash (Join-Path $response $name))){throw 'Collector signed bytes not restored'}
            }
            $script:checks++
        }
    }
    Remove-Item Function:\Get-AuthenticodeSignature
    # Detached response binding uses an in-memory leaf, never a certificate store/root.
    Add-Type -AssemblyName System.Security
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
    if($Thumbprint) {
        . (Join-Path $PSScriptRoot '..\scripts\WindowsStoreSigning.ps1')
        $cert=Get-EdRStoreSigningCertificate -Thumbprint $Thumbprint
    } else {
        $rsa=[Security.Cryptography.RSACryptoServiceProvider]::new(2048)
        $rsa.PersistKeyInCsp=$false
        $certRequest=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=EDR file exchange regression',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $cert=$certRequest.CreateSelfSigned([DateTimeOffset]::Now.AddMinutes(-1),[DateTimeOffset]::Now.AddDays(1))
    }
    try {
        $request2=Join-Path $scratch 'cms-request'; $response=Join-Path $scratch 'cms-response'
        New-SigningRequest $request2 manifest $commit '1.2.3' arm64 @($file)
        New-Item -ItemType Directory -Path $response | Out-Null
        Copy-Item $file $response
        $content=[Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes($file))
        $cms=[Security.Cryptography.Pkcs.SignedCms]::new($content,$true)
        $signer=[Security.Cryptography.Pkcs.CmsSigner]::new($cert)
        $signer.DigestAlgorithm=[Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
        if($Thumbprint) {
            Write-EdRStoreDetachedCms -ContentPath $file -SignaturePath (Join-Path $response 'artifact-manifest.json.p7s') -Thumbprint $Thumbprint -SignTool $SignTool
        } else {
            $cms.ComputeSignature($signer)
            [IO.File]::WriteAllBytes((Join-Path $response 'artifact-manifest.json.p7s'),$cms.Encode())
        }
        Write-ExchangeJson (Join-Path $response 'receipt.json') ([ordered]@{request_sha256=(Get-ExchangeHash (Join-Path $request2 'request.json'));publisher=$cert.Thumbprint})
        Assert-SigningResponse $request2 $response $cert.Thumbprint; $script:checks++
        Reject { Assert-SigningResponse $request2 $response $thumb }
        [IO.File]::WriteAllText((Join-Path $response 'artifact-manifest.json'),'tampered')
        Reject { Assert-SigningResponse $request2 $response $cert.Thumbprint }
        Copy-Item $file $response -Force
        Write-ExchangeJson (Join-Path $response 'receipt.json') ([ordered]@{request_sha256=('0'*64);publisher=$cert.Thumbprint})
        Reject { Assert-SigningResponse $request2 $response $cert.Thumbprint }
        # Installer exchange permits exactly one metadata edit: signed setup hash.
        $installer=Join-Path $scratch 'FDSecuritySetup.exe'
        $uiManifest=Join-Path $scratch 'setup-ui-manifest.json'
        [IO.File]::WriteAllBytes($installer,$original)
        Write-ExchangeJson $uiManifest ([ordered]@{version='1.2.3';setup_exe_sha256=(Get-ExchangeHash $installer);target_arch='arm64'})
        $installerRequest=Join-Path $scratch 'installer-request'
        $installerResponse=Join-Path $scratch 'installer-response'
        New-SigningRequest $installerRequest installer $commit '1.2.3' arm64 @($installer,$uiManifest)
        $null=Read-SigningRequest $installerRequest installer $commit '1.2.3' arm64
        New-Item -ItemType Directory -Path $installerResponse | Out-Null
        [BitConverter]::GetBytes([uint32]16).CopyTo($signed,300)
        $resultExe=Join-Path $installerResponse 'FDSecuritySetup.exe'
        [IO.File]::WriteAllBytes($resultExe,$signed)
        $m=Get-Content $uiManifest -Raw | ConvertFrom-Json
        $m.setup_exe_sha256=Get-ExchangeHash $resultExe
        $resultManifest=Join-Path $installerResponse 'setup-ui-manifest.json'
        Write-ExchangeJson $resultManifest $m
        if($Thumbprint) {
            Write-EdRStoreDetachedCms -ContentPath $resultManifest -SignaturePath ($resultManifest+'.p7s') -Thumbprint $Thumbprint -SignTool $SignTool
        } else {
            $installerCms=[Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes($resultManifest)),$true)
            $installerCms.ComputeSignature($signer)
            [IO.File]::WriteAllBytes(($resultManifest+'.p7s'),$installerCms.Encode())
        }
        Write-ExchangeJson (Join-Path $installerResponse 'receipt.json') ([ordered]@{request_sha256=(Get-ExchangeHash (Join-Path $installerRequest 'request.json'));publisher=$cert.Thumbprint})
        function Get-AuthenticodeSignature { param($LiteralPath)
            [pscustomobject]@{Status='Valid';SignerCertificate=$cert;TimeStamperCertificate=$true}
        }
        Assert-SigningResponse $installerRequest $installerResponse $cert.Thumbprint; $script:checks++
        $m.target_arch='amd64'; Write-ExchangeJson $resultManifest $m
        Reject { Assert-SigningResponse $installerRequest $installerResponse $cert.Thumbprint }
        Remove-Item Function:\Get-AuthenticodeSignature
    } finally { if(-not $Thumbprint){ $cert.Dispose(); $rsa.Dispose() } }
    if($Thumbprint) {
        . (Join-Path $PSScriptRoot '..\scripts\WindowsStoreSigning.ps1')
        $exe=Join-Path $scratch 'real-unsigned.exe'; $signedExe=Join-Path $scratch 'real-signed.exe'
        Add-Type -TypeDefinition 'public class ExchangeProbe { public static void Main() {} }' -OutputAssembly $exe -OutputType ConsoleApplication
        Copy-Item $exe $signedExe
        Invoke-EdRStoreAuthenticodeSign -Path $signedExe -Thumbprint $Thumbprint -SignTool $SignTool
        Assert-SignedExecutable $exe $signedExe $Thumbprint; $script:checks++
    }
    Write-Host "PASS: $script:checks file-only signing contract checks"
} finally { Remove-Item -LiteralPath $scratch -Recurse -Force }
