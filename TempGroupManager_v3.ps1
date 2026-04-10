#Requires -Version 5.1

<#
.SYNOPSIS
    Temporaere AD-Gruppenmitgliedschaften via AD PAM (TTL-basiert) — WPF/XAML Edition
.DESCRIPTION
    3-Schritt-WPF-GUI: 1. Benutzer  2. Gruppe  3. Freigabe
    Benoetigt: Windows Server 2016+ Domain Functional Level,
    AD PAM Feature aktiviert, RSAT-AD-PowerShell auf dem Admin-Rechner.

    Einmalige AD-Konfiguration (auf einem Domaenencontroller als Domain-Admin):
        Enable-ADOptionalFeature `
            -Identity 'Privileged Access Management Feature' `
            -Scope ForestOrConfigurationSet `
            -Target 'yourdomain.com'
.NOTES
    EventLog: Application / Source "TempGroupManager"
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
            -Properties Name, GroupCategory, GroupScope, Description `
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

function Add-TempMembership {
    param([string]$UserDN, [string]$GroupDN, [int]$Hours)
    Add-ADGroupMember -Identity $GroupDN -Members $UserDN `
        -MemberTimeToLive (New-TimeSpan -Hours $Hours)
    $operator = "$env:USERDOMAIN\$env:USERNAME auf $env:COMPUTERNAME"
    Write-AuditLog -EventId 1001 `
        -Message "Temporaere Mitgliedschaft hinzugefuegt: $UserDN -> $GroupDN ($Hours Stunden) | Operator: $operator"
}

function Write-AuditLog {
    param([int]$EventId, [string]$Message)
    $entryType = if ($EventId -eq 1099) { 'Error' } else { 'Information' }
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists('TempGroupManager')) {
            New-EventLog -LogName Application -Source 'TempGroupManager' -ErrorAction Stop
        }
        Write-EventLog -LogName Application -Source 'TempGroupManager' `
            -EventId $EventId -EntryType $entryType -Message $Message -ErrorAction Stop
    } catch {
        # Audit-Logging fehlgeschlagen — Warnung ausgeben statt still scheitern
        $script:AuditLogFailed = $true
        $script:AuditLogError  = $_.Exception.Message
    }
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
            @{ Header = 'Name';         Binding = 'Name';          Width = '*'   },
            @{ Header = 'Typ';          Binding = 'GroupCategory'; Width = '100' },
            @{ Header = 'Bereich';      Binding = 'GroupScope';    Width = '100' },
            @{ Header = 'Beschreibung'; Binding = 'Description';   Width = '160' }
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
                        -Filter "Name -like '*$safeTerm*'" `
                        -Properties Name, GroupCategory, GroupScope, Description `
                        -ResultSetSize 200 |
                    Sort-Object Name |
                    ForEach-Object {
                        [PSCustomObject]@{
                            Name          = $_.Name
                            GroupCategory = $_.GroupCategory.ToString()
                            GroupScope    = $_.GroupScope.ToString()
                            Description   = if ($_.Description) { $_.Description } else { '' }
                            _ADObject     = $_
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
    Title="Temporaere Gruppenmitgliedschaft  [AD PAM / TTL]"
    Width="680" MinWidth="550"
    Height="520" MinHeight="420"
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
        <Border DockPanel.Dock="Top" Background="{StaticResource AccentBrush}" Padding="16,12">
            <TextBlock Text="Temporaere Gruppenmitgliedschaft  [AD PAM / TTL]"
                       Foreground="White" FontSize="15" FontWeight="SemiBold"/>
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

                <!-- === KARTE 1: BENUTZER === -->
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
                            <TextBlock Text="1.   BENUTZER"
                                       Foreground="White" FontWeight="SemiBold"/>
                        </Border>

                        <!-- Card-Inhalt -->
                        <Grid Grid.Row="1" Margin="12,10,12,12">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>

                            <!-- Suchzeile -->
                            <Grid Grid.Row="0">
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
                            <TextBlock x:Name="TxtUserStatus" Grid.Row="1"
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
$txtUser        = $window.FindName('TxtUser')
$btnUserSearch  = $window.FindName('BtnUserSearch')
$txtUserStatus  = $window.FindName('TxtUserStatus')

$txtGroup       = $window.FindName('TxtGroup')
$btnGroupSearch = $window.FindName('BtnGroupSearch')
$txtGroupStatus = $window.FindName('TxtGroupStatus')

$txtDauer       = $window.FindName('TxtDauer')
$cmbUnit        = $window.FindName('CmbUnit')
$btnAdd         = $window.FindName('BtnAdd')

# Zustand
$script:SelectedUser   = $null
$script:SelectedGroup  = $null
$script:AuditLogFailed = $false
$script:AuditLogError  = ''

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
    $script:SelectedUser = $null
    Set-UserStatus -Text ([string][char]0x2014)
}

function Reset-GroupSelection {
    $script:SelectedGroup = $null
    Set-GroupStatus -Text ([string][char]0x2014)
}

# --- Benutzer direkt aufloesen (Enter in TextBox) ---

$resolveUser = {
    $text = $txtUser.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { Reset-UserSelection; return }
    $window.Cursor = [System.Windows.Input.Cursors]::Wait
    try {
        $u = Resolve-ADUser -Identity $text
        if ($null -eq $u) {
            $script:SelectedUser = $null
            Set-UserStatus -Text ([string][char]0x2718 + "  Benutzer nicht gefunden") -Color Error
        } elseif (-not $u.Enabled) {
            $script:SelectedUser = $null
            Set-UserStatus -Text ([string][char]0x2718 + "  Konto ist deaktiviert") -Color Error
        } else {
            $script:SelectedUser = $u
            $disp = if ($u.DisplayName) { $u.DisplayName } else { $u.SamAccountName }
            $dept = if ($u.Department)  { "  |  $($u.Department)" } else { '' }
            Set-UserStatus -Text ([string][char]0x2714 + "  $disp  ($($u.SamAccountName))$dept") -Color Success
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

# --- Benutzer Such-Dialog ---

$btnUserSearch.Add_Click({
    $result = Show-SearchDialog -Type User -Owner $window
    if ($null -ne $result) {
        $script:SelectedUser = $result
        $txtUser.Text = $result.SamAccountName
        $disp = if ($result.DisplayName) { $result.DisplayName } else { $result.SamAccountName }
        $dept = if ($result.Department)  { "  |  $($result.Department)" } else { '' }
        Set-UserStatus -Text ([string][char]0x2714 + "  $disp  ($($result.SamAccountName))$dept") -Color Success
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
            Set-GroupStatus -Text ([string][char]0x2714 + "  $($g.Name)  ($($g.GroupCategory) / $($g.GroupScope))") -Color Success
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
        Set-GroupStatus -Text ([string][char]0x2714 + "  $($result.Name)  ($($result.GroupCategory) / $($result.GroupScope))") -Color Success
    }
})

# --- Dauer-Eingabe: nur Zahlen erlauben ---

$txtDauer.Add_PreviewTextInput({
    param($s, $e)
    if ($e.Text -notmatch '^\d+$') { $e.Handled = $true }
})

# --- Mitgliedschaft hinzufuegen ---

$btnAdd.Add_Click({
    if ($null -eq $script:SelectedUser) {
        [System.Windows.MessageBox]::Show(
            $window,
            "Bitte zuerst einen Benutzer auswaehlen (Schritt 1).",
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
    $uName  = if ($script:SelectedUser.DisplayName) {
        $script:SelectedUser.DisplayName
    } else {
        $script:SelectedUser.SamAccountName
    }
    $unitTxt = if ($cmbUnit.SelectedIndex -eq 1) { 'Tag(e)' } else { 'Stunde(n)' }

    $confirm = [System.Windows.MessageBox]::Show(
        $window,
        "Benutzer : $uName`nGruppe   : $($script:SelectedGroup.Name)`nDauer    : $dauerVal $unitTxt`nAblauf   : $expiry`n`nMitgliedschaft hinzufuegen?",
        "Bestaetigung",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Question
    )
    if ($confirm -ne [System.Windows.MessageBoxResult]::Yes) { return }

    $window.Cursor = [System.Windows.Input.Cursors]::Wait
    try {
        Add-TempMembership `
            -UserDN  $script:SelectedUser.DistinguishedName `
            -GroupDN $script:SelectedGroup.DistinguishedName `
            -Hours   $hours

        # Auf fehlgeschlagenes Audit-Logging pruefen
        if ($script:AuditLogFailed) {
            $script:AuditLogFailed = $false
            [System.Windows.MessageBox]::Show(
                $window,
                "Mitgliedschaft wurde hinzugefuegt, aber der Audit-Log-Eintrag konnte nicht geschrieben werden.`n`nFehler: $script:AuditLogError`n`nAblauf: $expiry`n`nBitte EventLog-Berechtigungen pruefen (Quelle 'TempGroupManager' muss vorhanden sein).",
                "Warnung: Audit-Logging fehlgeschlagen",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning
            ) | Out-Null
        } else {
            [System.Windows.MessageBox]::Show(
                $window,
                "Mitgliedschaft erfolgreich hinzugefuegt.`nAblauf: $expiry",
                "Erfolg",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Information
            ) | Out-Null
        }

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
