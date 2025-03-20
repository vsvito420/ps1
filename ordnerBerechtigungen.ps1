# Das Skript ist fuer Windows Server 2019 | PowerShell-Skript für Windows Server 2019, das alle Sicherheitsgruppen eines Benutzers ausgibt und anschließend die Berechtigungen dieser Gruppen für einen ausgewählten Ordner anzeigt
# Laden der Windows Forms für den Ordnerauswahldialog
Add-Type -AssemblyName System.Windows.Forms

# Funktion zur Ordnerauswahl
function Select-Folder {
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Wählen Sie einen Ordner aus"
    $folderBrowser.RootFolder = [System.Environment+SpecialFolder]::MyComputer
    
    if ($folderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $folderBrowser.SelectedPath
    } else {
        return $null
    }
}

# Hauptskript
Clear-Host
Write-Host "Benutzergruppen und Ordnerberechtigungen" -ForegroundColor Cyan
Write-Host "--------------------------------------" -ForegroundColor Cyan

# 1. Ordnerauswahl
Write-Host "Bitte wählen Sie den Zielordner aus:" -ForegroundColor Green
$selectedFolder = Select-Folder

if (-not $selectedFolder) {
    Write-Host "Keine Ordnerauswahl getroffen. Das Skript wird beendet." -ForegroundColor Red
    exit
}

Write-Host "Ausgewählter Ordner: $selectedFolder" -ForegroundColor Yellow

# 2. Benutzerangabe
$userName = Read-Host "Geben Sie den Benutzernamen ein (z.B. 'domain\username' oder nur 'username')"

# 3. Überprüfen, ob das AD-Modul verfügbar ist
$adModuleAvailable = $false
try {
    if (Get-Module -Name ActiveDirectory -ListAvailable) {
        Import-Module ActiveDirectory
        $adModuleAvailable = $true
        Write-Host "Active Directory-Modul geladen." -ForegroundColor Green
    } else {
        Write-Host "Active Directory-Modul nicht verfügbar. Alternative Methode wird verwendet." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "Fehler beim Laden des AD-Moduls: $_" -ForegroundColor Yellow
}

# 4. Abrufen der Sicherheitsgruppen des Benutzers
Write-Host "Abrufen der Sicherheitsgruppen für Benutzer '$userName'..." -ForegroundColor Yellow

$groups = @()

if ($adModuleAvailable) {
    try {
        # AD-Methode für Gruppenabruf
        if ($userName -like "*\*") {
            $parts = $userName -split "\\"
            $domain = $parts[0]
            $user = $parts[1]
            $userObj = Get-ADUser -Identity $user -Properties MemberOf -Server $domain -ErrorAction Stop
        } else {
            $userObj = Get-ADUser -Identity $userName -Properties MemberOf -ErrorAction Stop
        }
        
        $userObj.MemberOf | ForEach-Object {
            $group = Get-ADGroup -Identity $_ -ErrorAction SilentlyContinue
            if ($group) {
                $groups += $group
            }
        }
        
        Write-Host "$($groups.Count) Gruppen gefunden." -ForegroundColor Green
    }
    catch {
        Write-Host "Fehler beim Abrufen der AD-Gruppen: $_" -ForegroundColor Red
        $adModuleAvailable = $false
    }
}

if (-not $adModuleAvailable -or $groups.Count -eq 0) {
    # Alternativmethode: Net User
    try {
        if ($userName -like "*\*") {
            $parts = $userName -split "\\"
            $user = $parts[1]
        } else {
            $user = $userName
        }
        
        $netUserOutput = net user $user /domain 2>$null
        
        if ($LASTEXITCODE -ne 0) {
            # Lokaler Benutzer
            $netUserOutput = net user $user 2>$null
        }
        
        if ($LASTEXITCODE -eq 0) {
            # Gruppenmitgliedschaften extrahieren
            $inGroupSection = $false
            $groupNames = @()
            
            foreach ($line in $netUserOutput) {
                if ($line -match "Lokale Gruppenmitgliedschaften" -or 
                    $line -match "Globale Gruppenmitgliedschaften" -or 
                    $line -match "Local Group Memberships" -or 
                    $line -match "Global Group memberships") {
                    $inGroupSection = $true
                    continue
                }
                
                if ($inGroupSection) {
                    if ([string]::IsNullOrWhiteSpace($line) -or $line -match "Der Befehl") {
                        $inGroupSection = $false
                        continue
                    }
                    
                    $line = $line.Replace("*", " ").Trim()
                    $lineGroups = $line -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                    
                    foreach ($group in $lineGroups) {
                        $groupNames += $group
                    }
                }
            }
            
            foreach ($groupName in $groupNames) {
                if (-not [string]::IsNullOrWhiteSpace($groupName)) {
                    $groups += [PSCustomObject]@{
                        Name = $groupName
                        SamAccountName = $groupName
                    }
                }
            }
            
            Write-Host "$($groups.Count) Gruppen gefunden." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Fehler beim Abrufen der Gruppen: $_" -ForegroundColor Red
    }
}

# Manuelle Gruppeneingabe falls nötig
if ($groups.Count -eq 0) {
    Write-Host "Keine Gruppen gefunden." -ForegroundColor Yellow
    $manualInput = Read-Host "Möchten Sie die Gruppen manuell eingeben? (J/N)"
    
    if ($manualInput -eq "J" -or $manualInput -eq "j") {
        do {
            $groupName = Read-Host "Geben Sie einen Gruppennamen ein (oder drücken Sie Enter zum Beenden)"
            
            if (-not [string]::IsNullOrWhiteSpace($groupName)) {
                $groups += [PSCustomObject]@{
                    Name = $groupName
                    SamAccountName = $groupName
                }
            }
        } while (-not [string]::IsNullOrWhiteSpace($groupName))
    }
}

if ($groups.Count -eq 0) {
    Write-Host "Keine Sicherheitsgruppen gefunden. Das Skript wird beendet." -ForegroundColor Red
    exit
}

# 5. Berechtigungen für jede Gruppe anzeigen
Write-Host "`nGruppenmitgliedschaften für '$userName' und Berechtigungen für '$selectedFolder':" -ForegroundColor Green
Write-Host "=========================================================================" -ForegroundColor Green

# ACL abrufen
try {
    $acl = Get-Acl -Path $selectedFolder -ErrorAction Stop
}
catch {
    Write-Host "Fehler beim Abrufen der Berechtigungen: $_" -ForegroundColor Red
    exit
}

foreach ($group in $groups) {
    $groupName = $group.Name
    Write-Host "`nGruppe: $groupName" -ForegroundColor Yellow
    
    # Mögliche Formatvarianten für Gruppenname in ACLs
    $possibleFormats = @(
        "$groupName",
        "*\$groupName",
        "BUILTIN\$groupName",
        "NT AUTHORITY\$groupName",
        "$env:COMPUTERNAME\$groupName"
    )
    
    if ($userName -like "*\*") {
        $domain = ($userName -split "\\")[0]
        $possibleFormats += "$domain\$groupName"
    }
    
    $permissions = $acl.Access | Where-Object { 
        $idRef = $_.IdentityReference.ToString()
        $found = $false
        
        foreach ($format in $possibleFormats) {
            if ($idRef -like $format) {
                $found = $true
                break
            }
        }
        
        $found
    }
    
    if (-not $permissions -or $permissions.Count -eq 0) {
        Write-Host "  Keine direkten Berechtigungen gefunden." -ForegroundColor Gray
    }
    else {
        foreach ($perm in $permissions) {
            Write-Host "  Identität: $($perm.IdentityReference)" -ForegroundColor White
            Write-Host "  Zugriffstyp: $($perm.AccessControlType)" -ForegroundColor Cyan
            Write-Host "  Rechte: $($perm.FileSystemRights)" -ForegroundColor Cyan
            Write-Host "  Vererbung: $($perm.InheritanceFlags)" -ForegroundColor Cyan
            Write-Host "  Propagierung: $($perm.PropagationFlags)" -ForegroundColor Cyan
            Write-Host "  ---" -ForegroundColor Gray
        }
    }
}

Write-Host "`nFertig!" -ForegroundColor Green
