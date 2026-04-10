#Requires -Version 5.1

<#
.SYNOPSIS
    Temporaere AD-Gruppenmitgliedschaften via AD PAM (TTL-basiert)
.DESCRIPTION
    WinForms-GUI zum Vergeben zeitlich begrenzter AD-Gruppenmitgliedschaften.
    Benoetigt: Windows Server 2016+ Domain Functional Level, AD PAM Feature
    aktiviert, RSAT-AD-PowerShell auf dem Admin-Rechner.

    Einmalige AD-Konfiguration (auf einem Domaenencontroller als Domain-Admin):
        Enable-ADOptionalFeature `
            -Identity 'Privileged Access Management Feature' `
            -Scope ForestOrConfigurationSet `
            -Target 'yourdomain.com'
.NOTES
    EventLog: Application / Source "TempGroupManager"
        1001 - Mitgliedschaft hinzugefuegt
        1002 - Mitgliedschaft manuell entfernt
        1099 - Fehler
#>

#region --- Assemblies ---
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
#endregion


#region --- ActiveDirectory-Modul ---
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    [System.Windows.Forms.MessageBox]::Show(
        "Das ActiveDirectory PowerShell-Modul ist nicht verfuegbar.`n`n" +
        "Bitte RSAT installieren:`n" +
        "Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0",
        "Modul fehlt",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit 1
}
#endregion

#region --- Hilfsfunktionen und AD-Logik ---

function Test-ADPAMAvailable {
    try {
        $feature = Get-ADOptionalFeature `
            -Filter { Name -eq 'Privileged Access Management Feature' } `
            -ErrorAction Stop
        return ($null -ne $feature -and $feature.EnabledScopes.Count -gt 0)
    } catch {
        return $false
    }
}

function Get-StringValue {
    param($Value)
    if ($null -eq $Value) { return '' }
    return $Value.ToString()
}

function Search-ADUsers {
    param([string]$Filter)
    if ([string]::IsNullOrWhiteSpace($Filter)) { return @() }
    $f = "Name -like '*$Filter*' -or SamAccountName -like '*$Filter*' -or EmailAddress -like '*$Filter*'"
    return @(
        Get-ADUser -Filter $f `
            -Properties DisplayName, SamAccountName, Department, Title, Enabled `
            -ResultSetSize 100 |
        Where-Object { $_.Enabled } |
        Sort-Object DisplayName
    )
}

function Get-TempMemberships {
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $groups = @(Get-ADGroup -Filter * -Properties member -ShowMemberTimeToLive -ResultSetSize 5000)
    foreach ($group in $groups) {
        if (-not $group.member) { continue }
        $ttlMembers = @($group.member | Where-Object { $_ -match '^<TTL=' })
        foreach ($m in $ttlMembers) {
            if ($m -notmatch '^<TTL=(\d+),(.+)>$') { continue }
            $ttlSec   = [int]$Matches[1]
            $memberDN = $Matches[2]
            try {
                $user = Get-ADUser -Identity $memberDN -Properties DisplayName -ErrorAction Stop
                $dispName = if ($user.DisplayName) { $user.DisplayName } else { $user.SamAccountName }
                $expiry   = (Get-Date).AddSeconds($ttlSec)
                $remaining = if ($ttlSec -ge 3600) {
                    '{0}h {1}min' -f [math]::Floor($ttlSec / 3600), [math]::Floor(($ttlSec % 3600) / 60)
                } else {
                    '{0}min' -f [math]::Floor($ttlSec / 60)
                }
                $results.Add([PSCustomObject]@{
                    DisplayName    = $dispName
                    SamAccountName = $user.SamAccountName
                    UserDN         = $memberDN
                    Group          = $group.Name
                    GroupDN        = $group.DistinguishedName
                    ExpiryTime     = $expiry
                    TTLSeconds     = $ttlSec
                    Remaining      = $remaining
                })
            } catch { }
        }
    }
    return $results
}

function Add-TempMembership {
    param([string]$UserDN, [string]$GroupDN, [int]$Hours)
    Add-ADGroupMember -Identity $GroupDN -Members $UserDN `
        -MemberTimeToLive (New-TimeSpan -Hours $Hours)
    Write-AuditLog -EventId 1001 `
        -Message "Temporaere Mitgliedschaft hinzugefuegt: $UserDN -> $GroupDN ($Hours Stunden)"
}

function Remove-TempMembership {
    param([string]$UserDN, [string]$GroupDN)
    Remove-ADGroupMember -Identity $GroupDN -Members $UserDN -Confirm:$false
    Write-AuditLog -EventId 1002 `
        -Message "Temporaere Mitgliedschaft entfernt: $UserDN aus $GroupDN"
}

function Write-AuditLog {
    param([int]$EventId, [string]$Message)
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists('TempGroupManager')) {
            New-EventLog -LogName Application -Source 'TempGroupManager'
        }
        Write-EventLog -LogName Application -Source 'TempGroupManager' `
            -EventId $EventId -EntryType Information -Message $Message
    } catch { }
}

#endregion

#region --- PAM-Verfuegbarkeit pruefen ---
if (-not (Test-ADPAMAvailable)) {
    [System.Windows.Forms.MessageBox]::Show(
        "Das AD PAM Feature ist in dieser Domain nicht aktiv.`n`n" +
        "Bitte einmalig auf einem Domaenencontroller ausfuehren:`n`n" +
        "  Enable-ADOptionalFeature ``n" +
        "    -Identity 'Privileged Access Management Feature' ``n" +
        "    -Scope ForestOrConfigurationSet ``n" +
        "    -Target 'yourdomain.com'`n`n" +
        "Anforderung: Domain Functional Level Windows Server 2016+",
        "Voraussetzung nicht erfuellt",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit 1
}
#endregion

#region --- GUI ---

# Zustand
$script:SelectedGroup = $null
$script:SelectedUser  = $null

# --- Hauptfenster ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "Temporaere Gruppenmitgliedschaft  [AD PAM / TTL]"
$form.Size = New-Object System.Drawing.Size(980, 760)
$form.MinimumSize = New-Object System.Drawing.Size(820, 640)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

# Root-Layout: 3 Zeilen
$rootLayout = New-Object System.Windows.Forms.TableLayoutPanel
$rootLayout.Dock = 'Fill'
$rootLayout.RowCount = 3
$rootLayout.ColumnCount = 1
[void]$rootLayout.RowStyles.Add(
    (New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 45)))
[void]$rootLayout.RowStyles.Add(
    (New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 52)))
[void]$rootLayout.RowStyles.Add(
    (New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 55)))
$form.Controls.Add($rootLayout)

# --- Hilfsfunktion: Such-GroupBox fuer Benutzer ---
function New-SearchGroupBox {
    param([string]$Title)

    $gb = New-Object System.Windows.Forms.GroupBox
    $gb.Text = $Title
    $gb.Dock = 'Fill'

    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'
    $layout.RowCount = 3
    $layout.ColumnCount = 2
    [void]$layout.RowStyles.Add(
        (New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 30)))
    [void]$layout.RowStyles.Add(
        (New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$layout.RowStyles.Add(
        (New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 22)))
    [void]$layout.ColumnStyles.Add(
        (New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 78)))
    [void]$layout.ColumnStyles.Add(
        (New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 22)))
    $layout.Padding = New-Object System.Windows.Forms.Padding(4, 2, 4, 2)

    $txtFilter = New-Object System.Windows.Forms.TextBox
    $txtFilter.Dock = 'Fill'

    $btnSearch = New-Object System.Windows.Forms.Button
    $btnSearch.Text = 'Suchen'
    $btnSearch.Dock = 'Fill'
    $btnSearch.FlatStyle = 'Flat'

    $lv = New-Object System.Windows.Forms.ListView
    $lv.Dock = 'Fill'
    $lv.View = 'Details'
    $lv.FullRowSelect = $true
    $lv.GridLines = $true
    $lv.MultiSelect = $false
    $lv.HideSelection = $false

    $lblSel = New-Object System.Windows.Forms.Label
    $lblSel.Text = 'Auswahl: (keine)'
    $lblSel.Dock = 'Fill'
    $lblSel.ForeColor = [System.Drawing.SystemColors]::GrayText

    $layout.Controls.Add($txtFilter, 0, 0)
    $layout.Controls.Add($btnSearch, 1, 0)
    $layout.Controls.Add($lv, 0, 1)
    $layout.SetColumnSpan($lv, 2)
    $layout.Controls.Add($lblSel, 0, 2)
    $layout.SetColumnSpan($lblSel, 2)

    $gb.Controls.Add($layout)

    return [PSCustomObject]@{
        Box    = $gb
        Filter = $txtFilter
        Button = $btnSearch
        List   = $lv
        Label  = $lblSel
    }
}

# --- Zeile 0: Gruppe (nativer Dialog) | Benutzer (Suche) ---
$searchRow = New-Object System.Windows.Forms.TableLayoutPanel
$searchRow.Dock = 'Fill'
$searchRow.ColumnCount = 2
$searchRow.RowCount = 1
[void]$searchRow.ColumnStyles.Add(
    (New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
[void]$searchRow.ColumnStyles.Add(
    (New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
$searchRow.Padding = New-Object System.Windows.Forms.Padding(4, 4, 4, 0)
$rootLayout.Controls.Add($searchRow, 0, 0)

# ---- Linke Haelfte: Nativer Windows-Gruppenauswahl-Dialog ----
$grpPickerGB = New-Object System.Windows.Forms.GroupBox
$grpPickerGB.Text = 'GRUPPE'
$grpPickerGB.Dock = 'Fill'

$grpPickerLayout = New-Object System.Windows.Forms.TableLayoutPanel
$grpPickerLayout.Dock = 'Fill'
$grpPickerLayout.RowCount = 3
$grpPickerLayout.ColumnCount = 1
[void]$grpPickerLayout.RowStyles.Add(
    (New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$grpPickerLayout.RowStyles.Add(
    (New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 32)))
[void]$grpPickerLayout.RowStyles.Add(
    (New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 22)))
$grpPickerLayout.Padding = New-Object System.Windows.Forms.Padding(4, 2, 4, 2)
$grpPickerGB.Controls.Add($grpPickerLayout)

# ListView zeigt die ausgewaehlte Gruppe (1 Zeile, wie im Benutzer-Panel)
$lvGrpSelected = New-Object System.Windows.Forms.ListView
$lvGrpSelected.Dock = 'Fill'
$lvGrpSelected.View = 'Details'
$lvGrpSelected.FullRowSelect = $true
$lvGrpSelected.GridLines = $true
$lvGrpSelected.MultiSelect = $false
$lvGrpSelected.HideSelection = $false
[void]$lvGrpSelected.Columns.Add('Name', 175)
[void]$lvGrpSelected.Columns.Add('Typ', 88)
[void]$lvGrpSelected.Columns.Add('Bereich', 95)
[void]$lvGrpSelected.Columns.Add('Beschreibung', 150)
$grpPickerLayout.Controls.Add($lvGrpSelected, 0, 0)

# Button oeffnet den nativen Windows-Dialog
$btnPickGroup = New-Object System.Windows.Forms.Button
$btnPickGroup.Text = 'Gruppe auswaehlen  (Windows-Dialog)...'
$btnPickGroup.Dock = 'Fill'
$btnPickGroup.FlatStyle = 'Flat'
$grpPickerLayout.Controls.Add($btnPickGroup, 0, 1)

$lblGrpSel = New-Object System.Windows.Forms.Label
$lblGrpSel.Text = 'Auswahl: (keine)'
$lblGrpSel.Dock = 'Fill'
$lblGrpSel.ForeColor = [System.Drawing.SystemColors]::GrayText
$grpPickerLayout.Controls.Add($lblGrpSel, 0, 2)

$searchRow.Controls.Add($grpPickerGB, 0, 0)

# ---- Rechte Haelfte: Benutzersuche (unveraendert) ----
$usrUI = New-SearchGroupBox -Title 'BENUTZER'
[void]$usrUI.List.Columns.Add('Anzeigename', 160)
[void]$usrUI.List.Columns.Add('Benutzerkonto', 120)
[void]$usrUI.List.Columns.Add('Abteilung', 120)
[void]$usrUI.List.Columns.Add('Position', 110)
$searchRow.Controls.Add($usrUI.Box, 1, 0)

# --- Zeile 1: Mitgliedschaft hinzufuegen ---
$addPanel = New-Object System.Windows.Forms.Panel
$addPanel.Dock = 'Fill'
$addPanel.Padding = New-Object System.Windows.Forms.Padding(10, 10, 8, 8)
$addPanel.BorderStyle = 'FixedSingle'
$rootLayout.Controls.Add($addPanel, 0, 1)

$lblDauer = New-Object System.Windows.Forms.Label
$lblDauer.Text = 'Dauer:'
$lblDauer.AutoSize = $true
$lblDauer.Location = New-Object System.Drawing.Point(0, 11)

$numDauer = New-Object System.Windows.Forms.NumericUpDown
$numDauer.Minimum = 1
$numDauer.Maximum = 720
$numDauer.Value = 8
$numDauer.Width = 58
$numDauer.Location = New-Object System.Drawing.Point(52, 8)

$cmbUnit = New-Object System.Windows.Forms.ComboBox
[void]$cmbUnit.Items.AddRange(@('Stunden', 'Tage'))
$cmbUnit.SelectedIndex = 0
$cmbUnit.DropDownStyle = 'DropDownList'
$cmbUnit.Width = 80
$cmbUnit.Location = New-Object System.Drawing.Point(118, 8)

$btnAdd = New-Object System.Windows.Forms.Button
$btnAdd.Text = 'Mitgliedschaft hinzufuegen'
$btnAdd.Width = 215
$btnAdd.Height = 27
$btnAdd.Location = New-Object System.Drawing.Point(212, 6)
$btnAdd.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$btnAdd.ForeColor = [System.Drawing.Color]::White
$btnAdd.FlatStyle = 'Flat'
$btnAdd.FlatAppearance.BorderSize = 0

$addPanel.Controls.AddRange(@($lblDauer, $numDauer, $cmbUnit, $btnAdd))

# --- Zeile 2: Aktive Mitgliedschaften ---
$memGB = New-Object System.Windows.Forms.GroupBox
$memGB.Text = 'Aktive temporaere Mitgliedschaften'
$memGB.Dock = 'Fill'
$memGB.Padding = New-Object System.Windows.Forms.Padding(4)
$rootLayout.Controls.Add($memGB, 0, 2)

$memLayout = New-Object System.Windows.Forms.TableLayoutPanel
$memLayout.Dock = 'Fill'
$memLayout.RowCount = 2
$memLayout.ColumnCount = 1
[void]$memLayout.RowStyles.Add(
    (New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$memLayout.RowStyles.Add(
    (New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 34)))
$memGB.Controls.Add($memLayout)

$lvMem = New-Object System.Windows.Forms.ListView
$lvMem.Dock = 'Fill'
$lvMem.View = 'Details'
$lvMem.FullRowSelect = $true
$lvMem.GridLines = $true
$lvMem.MultiSelect = $false
$lvMem.HideSelection = $false
[void]$lvMem.Columns.Add('Benutzer', 180)
[void]$lvMem.Columns.Add('Benutzerkonto', 130)
[void]$lvMem.Columns.Add('Gruppe', 170)
[void]$lvMem.Columns.Add('Laeuft ab', 145)
[void]$lvMem.Columns.Add('Verbleibend', 105)
$memLayout.Controls.Add($lvMem, 0, 0)

$memBtnPanel = New-Object System.Windows.Forms.Panel
$memBtnPanel.Dock = 'Fill'
$memLayout.Controls.Add($memBtnPanel, 0, 1)

$btnRemove = New-Object System.Windows.Forms.Button
$btnRemove.Text = 'Mitgliedschaft entfernen'
$btnRemove.Width = 195
$btnRemove.Height = 26
$btnRemove.Location = New-Object System.Drawing.Point(4, 3)
$btnRemove.FlatStyle = 'Flat'

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = 'Aktualisieren'
$btnRefresh.Width = 120
$btnRefresh.Height = 26
$btnRefresh.Location = New-Object System.Drawing.Point(206, 3)
$btnRefresh.FlatStyle = 'Flat'

$memBtnPanel.Controls.AddRange(@($btnRemove, $btnRefresh))

# --- Event-Handler ---

# Gruppen-Picker: Out-GridView (eingebaut in PowerShell, kein C# noetig)
$btnPickGroup.Add_Click({
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $allGroups = Get-ADGroup -Filter * `
            -Properties Name, GroupCategory, GroupScope, Description `
            -ResultSetSize 2000 |
            Sort-Object Name |
            Select-Object Name, GroupCategory, GroupScope, Description

        $form.Cursor = [System.Windows.Forms.Cursors]::Default

        $selected = $allGroups |
            Out-GridView -Title "AD-Gruppe auswaehlen  (Suche oben links im Fenster)" `
                         -OutputMode Single

        if ($selected) {
            $grp = Get-ADGroup -Identity $selected.Name `
                -Properties Name, GroupScope, GroupCategory, Description `
                -ErrorAction Stop
            $script:SelectedGroup = $grp

            $lvGrpSelected.Items.Clear()
            $item = New-Object System.Windows.Forms.ListViewItem($grp.Name)
            [void]$item.SubItems.Add($grp.GroupCategory.ToString())
            [void]$item.SubItems.Add($grp.GroupScope.ToString())
            [void]$item.SubItems.Add((Get-StringValue $grp.Description))
            [void]$lvGrpSelected.Items.Add($item)

            $lblGrpSel.Text      = "Auswahl: $($grp.Name)"
            $lblGrpSel.ForeColor = [System.Drawing.Color]::Black
        }
    } catch {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
        [System.Windows.Forms.MessageBox]::Show(
            "Fehler beim Laden der Gruppen:`n$_", 'Fehler', 'OK', 'Error') | Out-Null
    }
})

# Benutzersuche
$doUserSearch = {
    $usrUI.List.Items.Clear()
    $script:SelectedUser = $null
    $usrUI.Label.Text = 'Auswahl: (keine)'
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $users = Search-ADUsers -Filter $usrUI.Filter.Text
        foreach ($u in $users) {
            $dispName = if ($u.DisplayName) { $u.DisplayName } else { $u.SamAccountName }
            $item = New-Object System.Windows.Forms.ListViewItem($dispName)
            [void]$item.SubItems.Add($u.SamAccountName)
            [void]$item.SubItems.Add((Get-StringValue $u.Department))
            [void]$item.SubItems.Add((Get-StringValue $u.Title))
            $item.Tag = $u
            [void]$usrUI.List.Items.Add($item)
        }
        if ($users.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                'Keine Benutzer gefunden.', 'Suche', 'OK', 'Information') | Out-Null
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Fehler bei Benutzersuche:`n$_", 'Fehler', 'OK', 'Error') | Out-Null
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
}

$usrUI.Button.Add_Click($doUserSearch)
$usrUI.Filter.Add_KeyDown({
    param($s, $e)
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Return) { & $doUserSearch }
})
$usrUI.List.Add_SelectedIndexChanged({
    if ($usrUI.List.SelectedItems.Count -gt 0) {
        $u = $usrUI.List.SelectedItems[0].Tag
        $script:SelectedUser = $u
        $dispName = if ($u.DisplayName) { $u.DisplayName } else { $u.SamAccountName }
        $usrUI.Label.Text = "Auswahl: $dispName"
    }
})

# Refresh der Mitgliedschaftsliste
$doRefresh = {
    $lvMem.Items.Clear()
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $memberships = Get-TempMemberships
        foreach ($m in $memberships) {
            $item = New-Object System.Windows.Forms.ListViewItem($m.DisplayName)
            [void]$item.SubItems.Add($m.SamAccountName)
            [void]$item.SubItems.Add($m.Group)
            [void]$item.SubItems.Add($m.ExpiryTime.ToString('dd.MM.yyyy HH:mm'))
            [void]$item.SubItems.Add($m.Remaining)
            $item.Tag = $m
            [void]$lvMem.Items.Add($item)
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Fehler beim Laden der Mitgliedschaften:`n$_", 'Fehler', 'OK', 'Error') | Out-Null
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
}

$btnRefresh.Add_Click($doRefresh)

$btnAdd.Add_Click({
    if ($null -eq $script:SelectedGroup) {
        [System.Windows.Forms.MessageBox]::Show(
            'Bitte zuerst eine Gruppe auswaehlen.', 'Eingabe fehlt', 'OK', 'Warning') | Out-Null
        return
    }
    if ($null -eq $script:SelectedUser) {
        [System.Windows.Forms.MessageBox]::Show(
            'Bitte zuerst einen Benutzer auswaehlen.', 'Eingabe fehlt', 'OK', 'Warning') | Out-Null
        return
    }

    $hours  = if ($cmbUnit.SelectedIndex -eq 1) { [int]$numDauer.Value * 24 } else { [int]$numDauer.Value }
    $expiry = (Get-Date).AddHours($hours).ToString('dd.MM.yyyy HH:mm')
    $uName  = if ($script:SelectedUser.DisplayName) { $script:SelectedUser.DisplayName } else { $script:SelectedUser.SamAccountName }

    $result = [System.Windows.Forms.MessageBox]::Show(
        "Benutzer : $uName`nGruppe   : $($script:SelectedGroup.Name)`nAblauf   : $expiry`n`nHinzufuegen?",
        'Bestaetigung',
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )

    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        try {
            Add-TempMembership `
                -UserDN  $script:SelectedUser.DistinguishedName `
                -GroupDN $script:SelectedGroup.DistinguishedName `
                -Hours   $hours
            [System.Windows.Forms.MessageBox]::Show(
                "Mitgliedschaft erfolgreich hinzugefuegt.`nAblauf: $expiry",
                'Erfolg', 'OK', 'Information') | Out-Null
            & $doRefresh
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Fehler beim Hinzufuegen:`n$_", 'Fehler', 'OK', 'Error') | Out-Null
        } finally {
            $form.Cursor = [System.Windows.Forms.Cursors]::Default
        }
    }
})

$btnRemove.Add_Click({
    if ($lvMem.SelectedItems.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            'Bitte eine Mitgliedschaft auswaehlen.', 'Eingabe fehlt', 'OK', 'Warning') | Out-Null
        return
    }

    $mem = $lvMem.SelectedItems[0].Tag
    $result = [System.Windows.Forms.MessageBox]::Show(
        "$($mem.DisplayName) aus Gruppe '$($mem.Group)' entfernen?",
        'Bestaetigung',
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )

    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        try {
            Remove-TempMembership -UserDN $mem.UserDN -GroupDN $mem.GroupDN
            [System.Windows.Forms.MessageBox]::Show(
                'Mitgliedschaft entfernt.', 'Erfolg', 'OK', 'Information') | Out-Null
            & $doRefresh
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Fehler beim Entfernen:`n$_", 'Fehler', 'OK', 'Error') | Out-Null
        } finally {
            $form.Cursor = [System.Windows.Forms.Cursors]::Default
        }
    }
})

# Auto-Refresh alle 60 Sekunden
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 60000
$timer.Add_Tick($doRefresh)
$timer.Start()
$form.Add_FormClosed({ $timer.Stop(); $timer.Dispose() })

# Initialer Ladevorgang
& $doRefresh

# GUI starten
[System.Windows.Forms.Application]::Run($form)

#endregion
