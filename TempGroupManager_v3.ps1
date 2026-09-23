#Requires -Version 5.1

<#
.SYNOPSIS
    Temporaere AD-Gruppenmitgliedschaften via AD PAM (TTL-basiert) — WPF/XAML Edition
.DESCRIPTION
    3-Schritt-WPF-GUI: 1. Mitglied (Benutzer/Gruppe)  2. Gruppe  3. Freigabe
    Benoetigt: Windows Server 2016+ Domain Functional Level,
    AD PAM Feature aktiviert, RSAT-AD-PowerShell auf dem Admin-Rechner.

    Einmalige AD-Konfiguration (auf einem Domaenencontroller als Domain-Admin):
        Enable-ADOptionalFeature `
            -Identity 'Privileged Access Management Feature' `
            -Scope ForestOrConfigurationSet `
            -Target 'yourdomain.com'
.NOTES
    Autor       : Martin Lee Starke
    Version     : 1.1.0
    Aktualisiert: 23.09.2026

    Audit-Log   : TempGroupManager_audit.csv (im Script-Verzeichnis)
        1001 - Mitgliedschaft hinzugefuegt
        1099 - Fehler
#>

#region --- Assemblies ---
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Xml
#endregion

#region --- ActiveDirectory-Modul ---
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    [System.Windows.MessageBox]::Show(
        "Das ActiveDirectory PowerShell-Modul ist nicht verfuegbar.`n`n" +
        "Bitte RSAT installieren:`n" +
        "Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0",
        "Modul fehlt",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Error
    ) | Out-Null
    exit 1
}
#endregion

#region --- Datenmodell ---

# Echte CLR-Properties notwendig, damit WPF-DataGrid-Binding funktioniert.
# PSCustomObject-NoteProperties sind fuer WPFs Reflection-basiertes Binding unsichtbar.
class TempMember {
    [string]$Mitglied
    [string]$Typ
    [string]$Konto
    [string]$Gruppe
    [string]$Ablauf
    [string]$Verbleibend
    [string]$_MemberDN
    [string]$_GroupDN
    [int]   $_TTLSec
}

#endregion

#region --- Hilfsfunktionen ---

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

function Get-SafeSearchTerm {
    # Entfernt Zeichen, die den PowerShell-AD-Filter-Parser brechen koennen.
    # Hauptrisiko: einfache Anführungszeichen schliessen String-Literale im Filter
    # und ermöglichen Filter-Injection (z.B. "a' -or '1'='1").
    param([string]$Term)
    return ($Term -replace "['\(\)\\\/\x00]", '').Trim()
}

function Resolve-ADGroup {
    param([string]$Identity)
    if ([string]::IsNullOrWhiteSpace($Identity)) { return $null }
    try {
        return Get-ADGroup -Identity $Identity `
            -Properties Name, Description, member `
            -ErrorAction Stop
    } catch {
        return $null
    }
}

function Resolve-ADUser {
    param([string]$Identity)
    if ([string]::IsNullOrWhiteSpace($Identity)) { return $null }
    try {
        return Get-ADUser -Identity $Identity `
            -Properties DisplayName, SamAccountName, Department, Title, Enabled `
            -ErrorAction Stop
    } catch {
        return $null
    }
}

function Get-TempMemberships {
    $results = [System.Collections.Generic.List[TempMember]]::new()
    # -ShowMemberTimeToLive liefert TTL-Eintraege im Format <TTL=Sekunden,DN>
    # Nur Global-Gruppen abfragen — PAM nutzt ausschliesslich Global-Scope.
    # Das reduziert die LDAP-Treffermenge erheblich gegenueber -Filter *.
    $groups = @(Get-ADGroup -Filter "GroupScope -eq 'Global'" -Properties member -ShowMemberTimeToLive -ResultSetSize 2000)
    foreach ($group in $groups) {
        if (-not $group.member) { continue }
        $ttlMembers = @($group.member | Where-Object { $_ -match '^<TTL=' })
        foreach ($m in $ttlMembers) {
            if ($m -notmatch '^<TTL=(\d+)>,(.+)$') { continue }
            $ttlSec   = [int]$Matches[1]
            $memberDN = $Matches[2]
            try {
                $obj      = Get-ADObject -Identity $memberDN -Properties displayName, sAMAccountName, objectClass -ErrorAction Stop
                $dispName = if ($obj.displayName) { $obj.displayName } elseif ($obj.sAMAccountName) { $obj.sAMAccountName } else { $obj.Name }
                $typ      = switch ($obj.objectClass) {
                    'user'  { 'Benutzer' }
                    'group' { 'Gruppe' }
                    default { $obj.objectClass }
                }
                $expiry   = (Get-Date).AddSeconds($ttlSec)
                $remaining = if ($ttlSec -ge 3600) {
                    '{0}h {1}min' -f [math]::Floor($ttlSec / 3600), [math]::Floor(($ttlSec % 3600) / 60)
                } else {
                    '{0}min' -f [math]::Floor($ttlSec / 60)
                }
                $entry = [TempMember]::new()
                $entry.Mitglied    = $dispName
                $entry.Typ         = $typ
                $entry.Konto       = $obj.sAMAccountName
                $entry.Gruppe      = $group.Name
                $entry.Ablauf      = $expiry.ToString('dd.MM.yyyy HH:mm')
                $entry.Verbleibend = $remaining
                $entry._MemberDN   = $memberDN
                $entry._GroupDN    = $group.DistinguishedName
                $entry._TTLSec     = $ttlSec
                $results.Add($entry)
            } catch { }
        }
    }
    return ,[TempMember[]]@($results | Sort-Object _TTLSec)
}

function Add-TempMembership {
    param(
        [string]$MemberDN,
        [ValidateSet('Benutzer', 'Gruppe')]
        [string]$MemberType,
        [string]$GroupDN,
        [int]$Hours
    )
    Add-ADGroupMember -Identity $GroupDN -Members $MemberDN `
        -MemberTimeToLive (New-TimeSpan -Hours $Hours)
    $operator = "$env:USERDOMAIN\$env:USERNAME auf $env:COMPUTERNAME"
    Write-AuditLog -EventId 1001 `
        -Message "Temporaere Mitgliedschaft hinzugefuegt ($MemberType): $MemberDN -> $GroupDN ($Hours Stunden) | Operator: $operator"
}

function Write-AuditLog {
    param([int]$EventId, [string]$Message)
    try {
        $logFile = Join-Path $PSScriptRoot 'TempGroupManager_audit.csv'
        $line = [PSCustomObject]@{
            Zeitstempel = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            EventId     = $EventId
            Operator    = "$env:USERDOMAIN\$env:USERNAME"
            Computer    = $env:COMPUTERNAME
            Meldung     = $Message
        }
        $line | Export-Csv -Path $logFile -Append -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    } catch { }
}

function Show-ActiveMemberships {
    param([System.Windows.Window]$Owner)

    $xaml = @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Aktive temporaere Mitgliedschaften"
    Width="860" MinWidth="560"
    Height="480" MinHeight="300"
    WindowStartupLocation="CenterOwner"
    ShowInTaskbar="False"
    FontFamily="Segoe UI" FontSize="13">

    <Window.Resources>
        <Style x:Key="AccentBtn" TargetType="Button">
            <Setter Property="Background"      Value="#008444"/>
            <Setter Property="Foreground"      Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding"         Value="14,6"/>
            <Setter Property="Cursor"          Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" CornerRadius="3"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#005A9E"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="#BDBDBD"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="NeutralBtn" TargetType="Button">
            <Setter Property="Background"      Value="#EFEFEF"/>
            <Setter Property="Foreground"      Value="#222222"/>
            <Setter Property="BorderBrush"     Value="#BDBDBD"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding"         Value="14,6"/>
            <Setter Property="Cursor"          Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="3" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#E0E0E0"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <DockPanel>
        <!-- Header -->
        <Border DockPanel.Dock="Top" Background="#008444" Padding="14,10">
            <TextBlock Text="Aktive temporaere Mitgliedschaften" Foreground="White"
                       FontSize="14" FontWeight="SemiBold"/>
        </Border>

        <!-- Toolbar -->
        <Border DockPanel.Dock="Top" Background="#F5F5F5"
                BorderBrush="#E0E0E0" BorderThickness="0,0,0,1" Padding="12,7">
            <StackPanel Orientation="Horizontal">
                <Button x:Name="BtnRefresh" Content="Aktualisieren"
                        Style="{StaticResource AccentBtn}" Margin="0,0,12,0"/>
                <TextBlock x:Name="LblStatus" VerticalAlignment="Center"
                           Foreground="#767676" FontSize="11"/>
            </StackPanel>
        </Border>

        <!-- Button-Leiste unten -->
        <Border DockPanel.Dock="Bottom" Background="#F5F5F5"
                BorderBrush="#E0E0E0" BorderThickness="0,1,0,0" Padding="12,8">
            <Button x:Name="BtnClose" Content="Schliessen"
                    Style="{StaticResource NeutralBtn}"
                    HorizontalAlignment="Right" MinWidth="80"/>
        </Border>

        <!-- Tabelle -->
        <DataGrid x:Name="DgMemberships" Margin="12,8,12,0"
                  AutoGenerateColumns="False"
                  IsReadOnly="True"
                  SelectionMode="Single"
                  SelectionUnit="FullRow"
                  GridLinesVisibility="Horizontal"
                  HeadersVisibility="Column"
                  BorderBrush="#E0E0E0" BorderThickness="1"
                  RowBackground="White"
                  AlternatingRowBackground="#F8F8F8"
                  HorizontalScrollBarVisibility="Disabled"
                  VerticalScrollBarVisibility="Auto"
                  CanUserResizeRows="False"
                  CanUserAddRows="False">
            <DataGrid.Columns>
                <DataGridTextColumn Header="Mitglied"    Binding="{Binding Mitglied}"    Width="*"/>
                <DataGridTextColumn Header="Typ"         Binding="{Binding Typ}"         Width="80"/>
                <DataGridTextColumn Header="Konto"       Binding="{Binding Konto}"       Width="130"/>
                <DataGridTextColumn Header="Gruppe"      Binding="{Binding Gruppe}"      Width="*"/>
                <DataGridTextColumn Header="Ablauf"      Binding="{Binding Ablauf}"      Width="120"/>
                <DataGridTextColumn Header="Verbleibend" Binding="{Binding Verbleibend}" Width="90"/>
            </DataGrid.Columns>
        </DataGrid>
    </DockPanel>
</Window>
'@

    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
    $dlg = [Windows.Markup.XamlReader]::Load($reader)
    $dlg.Owner = $Owner

    $dg         = $dlg.FindName('DgMemberships')
    $btnRefresh = $dlg.FindName('BtnRefresh')
    $btnClose   = $dlg.FindName('BtnClose')
    $lblStatus  = $dlg.FindName('LblStatus')

    $loadData = {
        $lblStatus.Text    = 'Lade...'
        $dlg.Cursor        = [System.Windows.Input.Cursors]::Wait
        $dg.ItemsSource    = $null
        try {
            $items = Get-TempMemberships
            $dg.ItemsSource = $items
            $count = @($items).Count
            $lblStatus.Text = if ($count -eq 0) {
                'Keine aktiven Befristungen gefunden.'
            } else {
                "$count aktive Befristung(en)   |   Stand: $(Get-Date -Format 'HH:mm:ss')"
            }
        } catch {
            $lblStatus.Text = "Fehler: $_"
        } finally {
            $dlg.Cursor = $null
        }
    }

    $btnRefresh.Add_Click($loadData)
    $btnClose.Add_Click({ $dlg.Close() })

    # Beim Oeffnen sofort laden
    $dlg.Add_Loaded($loadData)

    $dlg.ShowDialog() | Out-Null
}

#endregion

#region --- PAM-Verfuegbarkeit pruefen ---
if (-not (Test-ADPAMAvailable)) {
    [System.Windows.MessageBox]::Show(
        "Das AD PAM Feature ist in dieser Domain nicht aktiv.`n`n" +
        "Bitte einmalig auf einem Domaenencontroller ausfuehren:`n`n" +
        "  Enable-ADOptionalFeature ``n" +
        "    -Identity 'Privileged Access Management Feature' ``n" +
        "    -Scope ForestOrConfigurationSet ``n" +
        "    -Target 'yourdomain.com'`n`n" +
        "Anforderung: Domain Functional Level Windows Server 2016+",
        "Voraussetzung nicht erfuellt",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Error
    ) | Out-Null
    exit 1
}
#endregion

#region --- XAML Such-Dialog ---

function Show-SearchDialog {
    param(
        [ValidateSet('Group', 'User')]
        [string]$Type,
        [System.Windows.Window]$Owner
    )

    $title  = if ($Type -eq 'User') { 'Benutzer suchen' } else { 'Gruppe suchen' }
    $header = if ($Type -eq 'User') { 'Benutzer auswaehlen' } else { 'Gruppe auswaehlen' }

    $dlgXaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="$title"
    Width="600" MinWidth="420"
    Height="480" MinHeight="320"
    WindowStartupLocation="CenterOwner"
    ShowInTaskbar="False"
    FontFamily="Segoe UI" FontSize="13">

    <Window.Resources>
        <Style TargetType="Button" x:Key="AccentBtn">
            <Setter Property="Background"      Value="#008444"/>
            <Setter Property="Foreground"      Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding"         Value="14,5"/>
            <Setter Property="Cursor"          Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" CornerRadius="3"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#005A9E"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="#BDBDBD"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style TargetType="Button" x:Key="NeutralBtn">
            <Setter Property="Background"      Value="#F0F0F0"/>
            <Setter Property="Foreground"      Value="#222222"/>
            <Setter Property="BorderBrush"     Value="#BDBDBD"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding"         Value="14,5"/>
            <Setter Property="Cursor"          Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="3" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#E0E0E0"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <DockPanel>
        <!-- Header -->
        <Border DockPanel.Dock="Top" Background="#008444" Padding="14,10">
            <TextBlock Text="$header" Foreground="White" FontSize="14" FontWeight="SemiBold"/>
        </Border>

        <!-- Button-Leiste unten -->
        <Border DockPanel.Dock="Bottom" Background="#F5F5F5"
                BorderBrush="#E0E0E0" BorderThickness="0,1,0,0" Padding="12,8">
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                <Button x:Name="BtnOK"     Content="OK"        Style="{StaticResource AccentBtn}"
                        IsEnabled="False"  Margin="0,0,8,0"    MinWidth="80"/>
                <Button x:Name="BtnCancel" Content="Abbrechen" Style="{StaticResource NeutralBtn}"
                        MinWidth="80"/>
            </StackPanel>
        </Border>

        <!-- Suchzeile -->
        <Grid DockPanel.Dock="Top" Margin="12,10,12,4">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBox x:Name="TxtSearch" Grid.Column="0" Margin="0,0,8,0"
                     MaxLength="256"
                     Padding="5,4" VerticalContentAlignment="Center"
                     BorderBrush="#BDBDBD" BorderThickness="1"/>
            <Button  x:Name="BtnSearch" Grid.Column="1" Content="Suchen"
                     Style="{StaticResource NeutralBtn}"/>
        </Grid>

        <!-- Status-Zeile (Treffer, Fehler, Ladehinweis) -->
        <TextBlock x:Name="LblStatus" DockPanel.Dock="Top"
                   Margin="12,0,12,4" FontSize="11" Foreground="#767676"
                   Text="Mindestens 2 Zeichen eingeben und Suchen druecken."/>

        <!-- Ergebnisliste -->
        <DataGrid x:Name="DgResults" Margin="12,0,12,8"
                  AutoGenerateColumns="False"
                  IsReadOnly="True"
                  SelectionMode="Single"
                  SelectionUnit="FullRow"
                  GridLinesVisibility="Horizontal"
                  HeadersVisibility="Column"
                  BorderBrush="#E0E0E0" BorderThickness="1"
                  RowBackground="White"
                  AlternatingRowBackground="#F8F8F8"
                  HorizontalScrollBarVisibility="Disabled"
                  VerticalScrollBarVisibility="Auto"
                  CanUserResizeRows="False"
                  CanUserAddRows="False"/>
    </DockPanel>
</Window>
"@

    $reader = [System.Xml.XmlReader]::Create(
        [System.IO.StringReader]::new($dlgXaml)
    )
    $dlg = [Windows.Markup.XamlReader]::Load($reader)
    $dlg.Owner = $Owner

    # DataGrid-Spalten je nach Typ
    if ($Type -eq 'User') {
        $cols = @(
            @{ Header = 'Anzeigename';   Binding = 'DisplayName';    Width = '*'   },
            @{ Header = 'Benutzerkonto'; Binding = 'SamAccountName'; Width = '130' },
            @{ Header = 'Abteilung';     Binding = 'Department';     Width = '130' }
        )
    } else {
        $cols = @(
            @{ Header = 'Name';         Binding = 'Name';        Width = '*'   },
            @{ Header = 'Beschreibung'; Binding = 'Description'; Width = '220' }
        )
    }

    $dg        = $dlg.FindName('DgResults')
    $txtSearch = $dlg.FindName('TxtSearch')
    $btnSearch = $dlg.FindName('BtnSearch')
    $btnOK     = $dlg.FindName('BtnOK')
    $btnCancel = $dlg.FindName('BtnCancel')
    $lblStatus = $dlg.FindName('LblStatus')

    foreach ($c in $cols) {
        $col        = New-Object System.Windows.Controls.DataGridTextColumn
        $col.Header = $c.Header
        $col.Binding = New-Object System.Windows.Data.Binding($c.Binding)
        $col.Width   = if ($c.Width -eq '*') {
            [System.Windows.Controls.DataGridLength]::new(
                1, [System.Windows.Controls.DataGridLengthUnitType]::Star)
        } else {
            [System.Windows.Controls.DataGridLength]::new([double]$c.Width)
        }
        $dg.Columns.Add($col)
    }

    $script:DlgResult = $null

    $doSearch = {
        $term = $txtSearch.Text.Trim()

        if ($term.Length -lt 2) {
            $lblStatus.Text       = 'Mindestens 2 Zeichen eingeben.'
            $lblStatus.Foreground = '#C75000'
            return
        }

        $safeTerm = Get-SafeSearchTerm -Term $term
        if ([string]::IsNullOrWhiteSpace($safeTerm)) {
            $lblStatus.Text       = 'Suchbegriff enthaelt nur unzulaessige Zeichen.'
            $lblStatus.Foreground = '#C75000'
            return
        }

        $dlg.Cursor           = [System.Windows.Input.Cursors]::Wait
        $dg.ItemsSource       = $null
        $btnOK.IsEnabled      = $false
        $lblStatus.Text       = 'Suche laeuft...'
        $lblStatus.Foreground = '#767676'

        try {
            if ($Type -eq 'User') {
                $items = @(
                    Get-ADUser `
                        -Filter "Name -like '*$safeTerm*' -or SamAccountName -like '*$safeTerm*'" `
                        -Properties DisplayName, SamAccountName, Department, Enabled `
                        -ResultSetSize 100 |
                    Where-Object { $_.Enabled } |
                    Sort-Object DisplayName |
                    ForEach-Object {
                        [PSCustomObject]@{
                            DisplayName    = if ($_.DisplayName) { $_.DisplayName } else { $_.SamAccountName }
                            SamAccountName = $_.SamAccountName
                            Department     = if ($_.Department)  { $_.Department  } else { '' }
                            _ADObject      = $_
                        }
                    }
                )
            } else {
                $items = @(
                    Get-ADGroup `
                        -Filter "Name -like '*$safeTerm*' -and GroupScope -eq 'Global'" `
                        -Properties Name, Description `
                        -ResultSetSize 200 |
                    Sort-Object Name |
                    ForEach-Object {
                        [PSCustomObject]@{
                            Name        = $_.Name
                            Description = if ($_.Description) { $_.Description } else { '' }
                            _ADObject   = $_
                        }
                    }
                )
            }
            $dg.ItemsSource       = $items
            $count                = $items.Count
            $lblStatus.Text       = if ($count -eq 0) {
                'Keine Ergebnisse gefunden.'
            } else {
                "$count Ergebnis(se) — Doppelklick oder OK zum Auswaehlen."
            }
            $lblStatus.Foreground = if ($count -eq 0) { '#767676' } else { '#107C10' }
        } catch {
            $lblStatus.Text       = "AD-Fehler: $_"
            $lblStatus.Foreground = '#A4262C'
        } finally {
            $dlg.Cursor = $null
        }
    }

    $btnSearch.Add_Click($doSearch)
    $txtSearch.Add_KeyDown({
        param($s, $e)
        if ($e.Key -eq [System.Windows.Input.Key]::Return) { & $doSearch }
    })

    $dg.Add_SelectionChanged({
        $btnOK.IsEnabled = ($null -ne $dg.SelectedItem)
    })
    $dg.Add_MouseDoubleClick({
        if ($null -ne $dg.SelectedItem) {
            $script:DlgResult = $dg.SelectedItem._ADObject
            $dlg.DialogResult = $true
        }
    })

    $btnOK.Add_Click({
        if ($null -ne $dg.SelectedItem) {
            $script:DlgResult = $dg.SelectedItem._ADObject
            $dlg.DialogResult = $true
        }
    })
    $btnCancel.Add_Click({ $dlg.DialogResult = $false })

    $dlg.ShowDialog() | Out-Null
    return $script:DlgResult
}

#endregion

#region --- Haupt-XAML ---

$mainXaml = @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="EXA Temp Gruppenmitgliedschaft  [AD PAM GUI]"
    Width="680" MinWidth="550"
    Height="560" MinHeight="450"
    WindowStartupLocation="CenterScreen"
    FontFamily="Segoe UI" FontSize="13">

    <Window.Resources>

        <!-- Brushes -->
        <SolidColorBrush x:Key="AccentBrush"   Color="#008444"/>
        <SolidColorBrush x:Key="SuccessBrush"  Color="#107C10"/>
        <SolidColorBrush x:Key="ErrorBrush"    Color="#A4262C"/>
        <SolidColorBrush x:Key="MutedBrush"    Color="#767676"/>
        <SolidColorBrush x:Key="CardBorderBrush" Color="#E0E0E0"/>
        <SolidColorBrush x:Key="CardBgBrush"   Color="White"/>
        <SolidColorBrush x:Key="AppBgBrush"    Color="#F0F2F5"/>

        <!-- Accent-Button -->
        <Style x:Key="AccentBtn" TargetType="Button">
            <Setter Property="Background"      Value="#008444"/>
            <Setter Property="Foreground"      Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding"         Value="14,6"/>
            <Setter Property="Cursor"          Value="Hand"/>
            <Setter Property="FontSize"        Value="13"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                CornerRadius="3"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#005A9E"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="#BDBDBD"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Neutral-Button -->
        <Style x:Key="NeutralBtn" TargetType="Button">
            <Setter Property="Background"      Value="#EFEFEF"/>
            <Setter Property="Foreground"      Value="#222222"/>
            <Setter Property="BorderBrush"     Value="#BDBDBD"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding"         Value="14,6"/>
            <Setter Property="Cursor"          Value="Hand"/>
            <Setter Property="FontSize"        Value="13"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="3"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#E0E0E0"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- TextBox -->
        <Style TargetType="TextBox">
            <Setter Property="Padding"         Value="6,5"/>
            <Setter Property="BorderBrush"     Value="#BDBDBD"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
        </Style>

        <!-- ComboBox -->
        <Style TargetType="ComboBox">
            <Setter Property="Padding"         Value="6,4"/>
            <Setter Property="BorderBrush"     Value="#BDBDBD"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
        </Style>

    </Window.Resources>

    <DockPanel Background="{StaticResource AppBgBrush}">

        <!-- === HEADER === -->
        <Border DockPanel.Dock="Top" Background="{StaticResource AccentBrush}" Padding="16,10">
            <Grid>
                <TextBlock Text="EXA Temp Gruppenmitgliedschaft  [AD PAM]"
                           Foreground="White" FontSize="15" FontWeight="SemiBold"
                           VerticalAlignment="Center"/>
                <Button x:Name="BtnShowActive"
                        Content="Aktive Befristungen"
                        HorizontalAlignment="Right"
                        Style="{StaticResource NeutralBtn}"
                        Padding="12,5" FontSize="12"/>
            </Grid>
        </Border>

        <!-- === INHALT (scrollbar fuer kleine Fenster) === -->
        <ScrollViewer VerticalScrollBarVisibility="Auto"
                      HorizontalScrollBarVisibility="Disabled">
            <Grid Margin="12">
                <Grid.RowDefinitions>
                    <RowDefinition Height="*"    MinHeight="110"/>
                    <RowDefinition Height="10"/>
                    <RowDefinition Height="*"    MinHeight="110"/>
                    <RowDefinition Height="10"/>
                    <RowDefinition Height="Auto" MinHeight="80"/>
                </Grid.RowDefinitions>

                <!-- === KARTE 1: MITGLIED (Benutzer oder Gruppe) === -->
                <Border Grid.Row="0"
                        Background="{StaticResource CardBgBrush}"
                        BorderBrush="{StaticResource CardBorderBrush}"
                        BorderThickness="1" CornerRadius="4">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>

                        <!-- Card-Header -->
                        <Border Grid.Row="0" Background="{StaticResource AccentBrush}"
                                CornerRadius="4,4,0,0" Padding="12,7">
                            <TextBlock Text="1.   MITGLIED"
                                       Foreground="White" FontWeight="SemiBold"/>
                        </Border>

                        <!-- Card-Inhalt -->
                        <Grid Grid.Row="1" Margin="12,10,12,12">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>

                            <!-- Typ-Auswahl -->
                            <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,8">
                                <RadioButton x:Name="RbMemberUser"  Content="Benutzer"
                                             GroupName="MemberType" IsChecked="True"
                                             Margin="0,0,16,0" VerticalContentAlignment="Center"/>
                                <RadioButton x:Name="RbMemberGroup" Content="Gruppe"
                                             GroupName="MemberType"
                                             VerticalContentAlignment="Center"/>
                            </StackPanel>

                            <!-- Suchzeile -->
                            <Grid Grid.Row="1">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBox x:Name="TxtUser"   Grid.Column="0" MaxLength="256"/>
                                <Button  x:Name="BtnUserSearch" Grid.Column="2"
                                         Content="Suchen..."
                                         Style="{StaticResource NeutralBtn}"/>
                            </Grid>

                            <!-- Status -->
                            <TextBlock x:Name="TxtUserStatus" Grid.Row="2"
                                       Text="&#x2014;"
                                       Foreground="{StaticResource MutedBrush}"
                                       Margin="0,8,0,0"
                                       TextWrapping="Wrap"
                                       VerticalAlignment="Center"/>
                        </Grid>
                    </Grid>
                </Border>

                <!-- === KARTE 2: GRUPPE === -->
                <Border Grid.Row="2"
                        Background="{StaticResource CardBgBrush}"
                        BorderBrush="{StaticResource CardBorderBrush}"
                        BorderThickness="1" CornerRadius="4">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>

                        <Border Grid.Row="0" Background="{StaticResource AccentBrush}"
                                CornerRadius="4,4,0,0" Padding="12,7">
                            <TextBlock Text="2.   GRUPPE"
                                       Foreground="White" FontWeight="SemiBold"/>
                        </Border>

                        <Grid Grid.Row="1" Margin="12,10,12,12">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>

                            <Grid Grid.Row="0">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBox x:Name="TxtGroup"      Grid.Column="0" MaxLength="256"/>
                                <Button  x:Name="BtnGroupSearch" Grid.Column="2"
                                         Content="Suchen..."
                                         Style="{StaticResource NeutralBtn}"/>
                            </Grid>

                            <TextBlock x:Name="TxtGroupStatus" Grid.Row="1"
                                       Text="&#x2014;"
                                       Foreground="{StaticResource MutedBrush}"
                                       Margin="0,8,0,0"
                                       TextWrapping="Wrap"
                                       VerticalAlignment="Center"/>
                        </Grid>
                    </Grid>
                </Border>

                <!-- === KARTE 3: FREIGABE === -->
                <Border Grid.Row="4"
                        Background="{StaticResource CardBgBrush}"
                        BorderBrush="{StaticResource CardBorderBrush}"
                        BorderThickness="1" CornerRadius="4">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>

                        <Border Grid.Row="0" Background="{StaticResource AccentBrush}"
                                CornerRadius="4,4,0,0" Padding="12,7">
                            <TextBlock Text="3.   FREIGABE"
                                       Foreground="White" FontWeight="SemiBold"/>
                        </Border>

                        <WrapPanel Grid.Row="1" Margin="12,10,12,12"
                                   Orientation="Horizontal" VerticalAlignment="Center">
                            <TextBlock Text="Dauer:" Margin="0,0,8,0"
                                       VerticalAlignment="Center"/>
                            <TextBox x:Name="TxtDauer"
                                     Width="70" Margin="0,0,8,0"
                                     Text="8" MaxLength="4"
                                     HorizontalContentAlignment="Center"/>
                            <ComboBox x:Name="CmbUnit" Width="100" Margin="0,0,16,0"
                                      SelectedIndex="0">
                                <ComboBoxItem Content="Stunden"/>
                                <ComboBoxItem Content="Tage"/>
                            </ComboBox>
                            <Button x:Name="BtnAdd"
                                    Content="Mitgliedschaft hinzufügen"
                                    Style="{StaticResource AccentBtn}"/>
                        </WrapPanel>
                    </Grid>
                </Border>

            </Grid>
        </ScrollViewer>
    </DockPanel>
</Window>
'@

#endregion

#region --- Fenster laden & Event-Handler ---

$reader = [System.Xml.XmlReader]::Create(
    [System.IO.StringReader]::new($mainXaml)
)
$window = [Windows.Markup.XamlReader]::Load($reader)

# Controls referenzieren
$rbMemberUser   = $window.FindName('RbMemberUser')
$rbMemberGroup  = $window.FindName('RbMemberGroup')
$txtUser        = $window.FindName('TxtUser')
$btnUserSearch  = $window.FindName('BtnUserSearch')
$txtUserStatus  = $window.FindName('TxtUserStatus')

$txtGroup       = $window.FindName('TxtGroup')
$btnGroupSearch = $window.FindName('BtnGroupSearch')
$txtGroupStatus = $window.FindName('TxtGroupStatus')

$txtDauer       = $window.FindName('TxtDauer')
$cmbUnit        = $window.FindName('CmbUnit')
$btnAdd         = $window.FindName('BtnAdd')
$btnShowActive  = $window.FindName('BtnShowActive')

# Zustand
# SelectedMember: ADUser oder ADGroup, je nach gewaehltem Typ in Karte 1
$script:SelectedMember = $null
$script:SelectedGroup = $null

# --- Hilfsfunktionen fuer Status-TextBlock ---

function Set-UserStatus {
    param([string]$Text, [string]$Color = 'Muted')
    $txtUserStatus.Text = $Text
    $txtUserStatus.Foreground = switch ($Color) {
        'Success' { '#107C10' }
        'Error'   { '#A4262C' }
        default   { '#767676' }
    }
}

function Set-GroupStatus {
    param([string]$Text, [string]$Color = 'Muted')
    $txtGroupStatus.Text = $Text
    $txtGroupStatus.Foreground = switch ($Color) {
        'Success' { '#107C10' }
        'Error'   { '#A4262C' }
        default   { '#767676' }
    }
}

function Reset-UserSelection {
    $script:SelectedMember = $null
    Set-UserStatus -Text ([string][char]0x2014)
}

function Reset-GroupSelection {
    $script:SelectedGroup = $null
    Set-GroupStatus -Text ([string][char]0x2014)
}

# --- Mitglied: Typ-Umschaltung und Anzeige ---

function Get-MemberType {
    if ($rbMemberGroup.IsChecked) { return 'Gruppe' }
    return 'Benutzer'
}

function Set-MemberSelection {
    # Uebernimmt ein aufgeloestes Mitglied (ADUser oder ADGroup) und zeigt es an
    param($Member)
    $script:SelectedMember = $Member
    if ((Get-MemberType) -eq 'Gruppe') {
        $count = @($Member.member).Count
        Set-UserStatus -Text ([string][char]0x2714 + "  Gruppe: $($Member.Name)  ($count direkte Mitglieder)") -Color Success
    } else {
        $disp = if ($Member.DisplayName) { $Member.DisplayName } else { $Member.SamAccountName }
        $dept = if ($Member.Department)  { "  |  $($Member.Department)" } else { '' }
        Set-UserStatus -Text ([string][char]0x2714 + "  $disp  ($($Member.SamAccountName))$dept") -Color Success
    }
}

$onMemberTypeChanged = {
    $txtUser.Text = ''
    Reset-UserSelection
}
$rbMemberUser.Add_Checked($onMemberTypeChanged)
$rbMemberGroup.Add_Checked($onMemberTypeChanged)

# --- Mitglied direkt aufloesen (Enter in TextBox) ---

$resolveUser = {
    $text = $txtUser.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { Reset-UserSelection; return }
    $window.Cursor = [System.Windows.Input.Cursors]::Wait
    try {
        if ((Get-MemberType) -eq 'Gruppe') {
            $g = Resolve-ADGroup -Identity $text
            if ($null -eq $g) {
                $script:SelectedMember = $null
                Set-UserStatus -Text ([string][char]0x2718 + "  Gruppe nicht gefunden") -Color Error
            } elseif ($g.GroupScope -ne 'Global') {
                $script:SelectedMember = $null
                Set-UserStatus -Text ([string][char]0x2718 + "  Nur globale Gruppen koennen Mitglied werden") -Color Error
            } else {
                Set-MemberSelection -Member $g
            }
        } else {
            $u = Resolve-ADUser -Identity $text
            if ($null -eq $u) {
                $script:SelectedMember = $null
                Set-UserStatus -Text ([string][char]0x2718 + "  Benutzer nicht gefunden") -Color Error
            } elseif (-not $u.Enabled) {
                $script:SelectedMember = $null
                Set-UserStatus -Text ([string][char]0x2718 + "  Konto ist deaktiviert") -Color Error
            } else {
                Set-MemberSelection -Member $u
            }
        }
    } finally {
        $window.Cursor = $null
    }
}

$txtUser.Add_KeyDown({
    param($s, $e)
    if ($e.Key -eq [System.Windows.Input.Key]::Return) { & $resolveUser }
})
$txtUser.Add_TextChanged({
    if ([string]::IsNullOrWhiteSpace($txtUser.Text)) { Reset-UserSelection }
})

# --- Mitglied Such-Dialog ---

$btnUserSearch.Add_Click({
    if ((Get-MemberType) -eq 'Gruppe') {
        $result = Show-SearchDialog -Type Group -Owner $window
        if ($null -ne $result) {
            # Suchergebnis enthaelt kein member-Attribut -> fuer die Mitgliederzahl nachladen
            $result = Resolve-ADGroup -Identity $result.DistinguishedName
            if ($null -ne $result) {
                $txtUser.Text = $result.Name
                Set-MemberSelection -Member $result
            }
        }
    } else {
        $result = Show-SearchDialog -Type User -Owner $window
        if ($null -ne $result) {
            $txtUser.Text = $result.SamAccountName
            Set-MemberSelection -Member $result
        }
    }
})

# --- Gruppe direkt aufloesen (Enter in TextBox) ---

$resolveGroup = {
    $text = $txtGroup.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { Reset-GroupSelection; return }
    $window.Cursor = [System.Windows.Input.Cursors]::Wait
    try {
        $g = Resolve-ADGroup -Identity $text
        if ($null -eq $g) {
            $script:SelectedGroup = $null
            Set-GroupStatus -Text ([string][char]0x2718 + "  Gruppe nicht gefunden") -Color Error
        } else {
            $script:SelectedGroup = $g
            Set-GroupStatus -Text ([string][char]0x2714 + "  $($g.Name)") -Color Success
        }
    } finally {
        $window.Cursor = $null
    }
}

$txtGroup.Add_KeyDown({
    param($s, $e)
    if ($e.Key -eq [System.Windows.Input.Key]::Return) { & $resolveGroup }
})
$txtGroup.Add_TextChanged({
    if ([string]::IsNullOrWhiteSpace($txtGroup.Text)) { Reset-GroupSelection }
})

# --- Gruppe Such-Dialog ---

$btnGroupSearch.Add_Click({
    $result = Show-SearchDialog -Type Group -Owner $window
    if ($null -ne $result) {
        $script:SelectedGroup = $result
        $txtGroup.Text = $result.Name
        Set-GroupStatus -Text ([string][char]0x2714 + "  $($result.Name)") -Color Success
    }
})

# --- Aktive Befristungen anzeigen ---

$btnShowActive.Add_Click({
    Show-ActiveMemberships -Owner $window
})

# --- Dauer-Eingabe: nur Zahlen erlauben ---

$txtDauer.Add_PreviewTextInput({
    param($s, $e)
    if ($e.Text -notmatch '^\d+$') { $e.Handled = $true }
})

# --- Mitgliedschaft hinzufuegen ---

$btnAdd.Add_Click({
    if ($null -eq $script:SelectedMember) {
        [System.Windows.MessageBox]::Show(
            $window,
            "Bitte zuerst ein Mitglied (Benutzer oder Gruppe) auswaehlen (Schritt 1).",
            "Eingabe fehlt",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning
        ) | Out-Null
        return
    }
    if ($null -eq $script:SelectedGroup) {
        [System.Windows.MessageBox]::Show(
            $window,
            "Bitte zuerst eine Gruppe auswaehlen (Schritt 2).",
            "Eingabe fehlt",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning
        ) | Out-Null
        return
    }

    $memberType = Get-MemberType

    if ($memberType -eq 'Gruppe' -and
        $script:SelectedMember.DistinguishedName -eq $script:SelectedGroup.DistinguishedName) {
        [System.Windows.MessageBox]::Show(
            $window,
            "Eine Gruppe kann nicht Mitglied von sich selbst werden.",
            "Ungueltige Auswahl",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning
        ) | Out-Null
        return
    }

    $dauerVal = 0
    if (-not [int]::TryParse($txtDauer.Text.Trim(), [ref]$dauerVal) -or $dauerVal -lt 1) {
        [System.Windows.MessageBox]::Show(
            $window,
            "Bitte eine gueltige Dauer (ganze Zahl >= 1) eingeben.",
            "Ungueltige Dauer",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning
        ) | Out-Null
        return
    }

    $hours  = if ($cmbUnit.SelectedIndex -eq 1) { $dauerVal * 24 } else { $dauerVal }

    # Maximale TTL: 1 Jahr (8760 Stunden) — Sicherheitsgrenze fuer PAM
    $maxHours = 8760
    if ($hours -gt $maxHours) {
        [System.Windows.MessageBox]::Show(
            $window,
            "Die maximale Dauer betraegt 1 Jahr (8760 Stunden).`nEingegebener Wert: $hours Stunden.",
            "Dauer zu gross",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning
        ) | Out-Null
        return
    }

    $expiry = (Get-Date).AddHours($hours).ToString('dd.MM.yyyy HH:mm')
    $unitTxt = if ($cmbUnit.SelectedIndex -eq 1) { 'Tag(e)' } else { 'Stunde(n)' }

    if ($memberType -eq 'Gruppe') {
        $memberCount = @($script:SelectedMember.member).Count
        $confirmText = "Mitglied  : $($script:SelectedMember.Name)`n" +
                       "Typ       : Gruppe (aktuell $memberCount direkte Mitglieder)`n" +
                       "Zielgruppe: $($script:SelectedGroup.Name)`n" +
                       "Dauer     : $dauerVal $unitTxt`nAblauf    : $expiry`n`n" +
                       "Achtung: Alle aktuellen und kuenftigen Mitglieder dieser Gruppe " +
                       "erhalten den Zugriff.`n`nMitgliedschaft hinzufuegen?"
        $confirmIcon = [System.Windows.MessageBoxImage]::Warning
    } else {
        $uName = if ($script:SelectedMember.DisplayName) {
            $script:SelectedMember.DisplayName
        } else {
            $script:SelectedMember.SamAccountName
        }
        $confirmText = "Benutzer : $uName`nGruppe   : $($script:SelectedGroup.Name)`nDauer    : $dauerVal $unitTxt`nAblauf   : $expiry`n`nMitgliedschaft hinzufuegen?"
        $confirmIcon = [System.Windows.MessageBoxImage]::Question
    }

    $confirm = [System.Windows.MessageBox]::Show(
        $window,
        $confirmText,
        "Bestaetigung",
        [System.Windows.MessageBoxButton]::YesNo,
        $confirmIcon
    )
    if ($confirm -ne [System.Windows.MessageBoxResult]::Yes) { return }

    $window.Cursor = [System.Windows.Input.Cursors]::Wait
    try {
        Add-TempMembership `
            -MemberDN   $script:SelectedMember.DistinguishedName `
            -MemberType $memberType `
            -GroupDN    $script:SelectedGroup.DistinguishedName `
            -Hours      $hours

        [System.Windows.MessageBox]::Show(
                $window,
                "Mitgliedschaft erfolgreich hinzugefuegt.`nAblauf: $expiry",
                "Erfolg",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Information
            ) | Out-Null

        # Reset
        $txtUser.Text  = ''
        $txtGroup.Text = ''
        Reset-UserSelection
        Reset-GroupSelection
    } catch {
        Write-AuditLog -EventId 1099 -Message "Fehler: $_"
        [System.Windows.MessageBox]::Show(
            $window,
            "Fehler beim Hinzufuegen:`n$_",
            "Fehler",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        ) | Out-Null
    } finally {
        $window.Cursor = $null
    }
})

#endregion

# Fenster starten
$window.ShowDialog() | Out-Null
