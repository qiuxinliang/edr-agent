// Inno's normal disk-space warning can be accepted by /SUPPRESSMSGBOXES.
// Keep this fail-closed check before any Stop-Service, enrollment copy or file
// replacement. The new package computes the local floor itself so supported
// old embedded updaters do not need to know the new optional command argument.
function EdrParseSpaceFloor(const Value: string; var Bytes: Int64): Boolean;
var
  I, Digit: Integer;
begin
  Result := False;
  Bytes := 0;
  if Value = '' then Exit;
  for I := 1 to Length(Value) do
  begin
    if (Value[I] < '0') or (Value[I] > '9') then Exit;
    Digit := Ord(Value[I]) - Ord('0');
    if Bytes > (9007199254740991 - Digit) div 10 then Exit;
    Bytes := Bytes * 10 + Digit;
  end;
  Result := True;
end;

function EdrReadSpaceFloor(var Bytes: Int64): string;
var
  I, EqPos: Integer;
  Found: Boolean;
  Arg, Key: string;
begin
  Result := '';
  Bytes := 0;
  Found := False;
  for I := 1 to ParamCount do
  begin
    Arg := ParamStr(I);
    EqPos := Pos('=', Arg);
    Key := Arg;
    if EqPos > 0 then Key := Copy(Arg, 1, EqPos - 1);
    if CompareText(Key, '/EDR_MIN_FREE_BYTES') = 0 then
    begin
      if Found or (EqPos = 0) then
      begin
        Result := 'EDR: duplicate or missing /EDR_MIN_FREE_BYTES value.';
        Exit;
      end;
      Found := True;
      if not EdrParseSpaceFloor(Copy(Arg, EqPos + 1, Length(Arg)), Bytes) then
      begin
        Result := 'EDR: /EDR_MIN_FREE_BYTES must be decimal bytes in 0..9007199254740991.';
        Exit;
      end;
    end;
  end;
  // Missing is compatible with old clients; local preflight below is mandatory.
end;

function EdrExistingSpaceDirectory(Path: string): string;
var
  Parent: string;
begin
  Result := '';
  while Path <> '' do
  begin
    if DirExists(Path) then
    begin
      Result := Path;
      Exit;
    end;
    Parent := ExtractFileDir(RemoveBackslashUnlessRoot(Path));
    if Parent = Path then Exit;
    Path := Parent;
  end;
end;

function EdrCheckSpaceDirectory(const LabelText, Path: string;
  const FloorBytes, GrowthBytes: Int64): string;
var
  Existing: string;
  FreeBytes, TotalBytes: Int64;
begin
  Result := '';
  Existing := EdrExistingSpaceDirectory(Path);
  if (Existing = '') or not GetSpaceOnDisk64(Existing, FreeBytes, TotalBytes) then
  begin
    Result := 'EDR: cannot measure free space for ' + LabelText + ' directory.';
    Exit;
  end;
  // Subtract after comparing: addition must not wrap for a large local floor.
  if (FreeBytes < FloorBytes) or (FreeBytes - FloorBytes < GrowthBytes) then
    Result := 'EDR: insufficient disk space for ' + LabelText +
      '; free=' + IntToStr(FreeBytes) + '; floor=' + IntToStr(FloorBytes) +
      '; installation_growth=' + IntToStr(GrowthBytes) + ' bytes.';
end;

function EdrAddSpaceBytes(var Total: Int64; const Bytes: Int64): Boolean;
begin
  Result := False;
  if (Total < 0) or (Total > 9007199254740991) or (Bytes < 0) then Exit;
  if Bytes > 9007199254740991 - Total then Exit;
  Total := Total + Bytes;
  Result := True;
end;

function EdrSpacePsQuote(const Value: string): string;
var
  Quoted: string;
begin
  Quoted := Value;
  StringChangeEx(Quoted, #39, #39 + #39, True);
  Result := #39 + Quoted + #39;
end;

function EdrComputeLocalSpaceFloor(const AppDir: string; const Required: Boolean;
  const PassedFloor: Int64; var FloorBytes: Int64): string;
var
  Code, Extracted: Integer;
  ProbeDir, ProbeExe, OutputPath, ConfigPath, Arguments, Command: string;
  Decimal: AnsiString;
begin
  Result := '';
  // Bound bootstrap extraction before writing temporary payloads. The final
  // admission below uses the independently computed local floor. This early
  // check cannot know the legacy client's local owner inventory yet.
  Result := EdrCheckSpaceDirectory('preflight extraction', ExpandConstant('{tmp}'),
    PassedFloor, {#EdrExpandedBytes});
  if Result <> '' then Exit;
  ConfigPath := AppDir + '\agent.toml';
  if Required and not FileExists(ConfigPath) then
  begin
    Result := 'EDR: existing configuration is required for storage preflight.';
    Exit;
  end;
  try
    // Use the package's own signed code and exact existing app-local closure;
    // never run a stale installed executable or download a helper.
    Extracted := ExtractTemporaryFiles('{app}\FDSensor.exe');
    if Extracted <> 1 then RaiseException('preflight executable is ambiguous');
#if EdrPreflightDllBytes > 0
    ExtractTemporaryFiles('{app}\*.dll');
#endif
    ProbeDir := ExpandConstant('{tmp}') + '\{app}';
    ProbeExe := ProbeDir + '\FDSensor.exe';
    OutputPath := ExpandConstant('{tmp}\edr-storage-space.floor');
    if FileExists(OutputPath) then DeleteFile(OutputPath);
    Arguments := '''--storage-space-preflight --output ''+[char]34+' +
      EdrSpacePsQuote(OutputPath) + '+[char]34';
    if FileExists(ConfigPath) then
      Arguments := Arguments + '+'' --config ''+[char]34+' +
        EdrSpacePsQuote(ConfigPath) + '+[char]34'
    else
      Arguments := Arguments + '+'' --defaults''';
    // Bound the existing local PowerShell process launcher. It waits for only
    // this child and kills only that PID on timeout; no Agent process matching.
    Command := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "'
      + '$ErrorActionPreference=''Stop'';$p=Start-Process -FilePath '
      + EdrSpacePsQuote(ProbeExe) + ' -ArgumentList '
      + '(' + Arguments + ')' + ' -WorkingDirectory ' + EdrSpacePsQuote(ProbeDir)
      + ' -PassThru;try{if(-not $p.WaitForExit(15000)){$p.Kill();exit 124};'
      + '$p.Refresh();exit $p.ExitCode}finally{$p.Dispose()}"';
    if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
      Command, ProbeDir, SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
    begin
      Result := 'EDR: local storage preflight failed; existing runtime was not stopped.';
      Exit;
    end;
    if not LoadStringFromFile(OutputPath, Decimal) or
       not EdrParseSpaceFloor(String(Decimal), FloorBytes) then
    begin
      Result := 'EDR: local storage preflight returned invalid bytes.';
      Exit;
    end;
    if PassedFloor > FloorBytes then FloorBytes := PassedFloor;
  except
    Result := 'EDR: local storage preflight extraction or execution failed.';
  end;
end;

function EdrCheckInstallSpace(const AppDir: string; const Required: Boolean): string;
var
  FloorBytes, PassedFloor, GrowthBytes, EngineBytes, OldLifecycleBytes: Int64;
  I: Integer;
  LifecyclePath: string;
begin
  Result := EdrReadSpaceFloor(PassedFloor);
  if Result <> '' then Exit;
  Result := EdrComputeLocalSpaceFloor(AppDir, Required, PassedFloor, FloorBytes);
  if Result <> '' then Exit;
  // Inno extracts a replacement into a new destination .tmp before deleting
  // the old file. Reserve every new file in full: do not credit deletion of
  // any old file or the parent's already-created rollback backup.
  GrowthBytes := {#EdrExpandedBytes};
  // The running Setup engine becomes the new uninstaller. Its bytes are not
  // a [Files] entry. Old lifecycle files can coexist with the replacement.
  if not FileSize64(ParamStr(0), EngineBytes) or (EngineBytes < 0) then
  begin
    Result := 'EDR: cannot measure the Setup engine for installation space.';
    Exit;
  end;
  if not EdrAddSpaceBytes(GrowthBytes, EngineBytes) then
  begin
    Result := 'EDR: installation space arithmetic overflow.';
    Exit;
  end;
  for I := 0 to 2 do
  begin
    LifecyclePath := AppDir + '\unins000.';
    if I = 0 then LifecyclePath := LifecyclePath + 'exe';
    if I = 1 then LifecyclePath := LifecyclePath + 'dat';
    if I = 2 then LifecyclePath := LifecyclePath + 'msg';
    if FileExists(LifecyclePath) then
    begin
      if not FileSize64(LifecyclePath, OldLifecycleBytes) or (OldLifecycleBytes < 0) then
      begin
        Result := 'EDR: cannot measure existing Inno lifecycle files.';
        Exit;
      end;
      if not EdrAddSpaceBytes(GrowthBytes, OldLifecycleBytes) then
      begin
        Result := 'EDR: installation space arithmetic overflow.';
        Exit;
      end;
    end;
  end;
  if (GrowthBytes < 0) or (GrowthBytes > 9007199254740991) then
  begin
    Result := 'EDR: installation space arithmetic overflow.';
    Exit;
  end;
  Log('EDR space: expanded_files={#EdrExpandedBytes}; installation_growth=' +
    IntToStr(GrowthBytes) + '; floor=' + IntToStr(FloorBytes));
  Result := EdrCheckSpaceDirectory('installation', AppDir, FloorBytes, GrowthBytes);
  if Result <> '' then Exit;
  // Check the actual temporary directory too, including mounted directories.
  // The same conservative growth allowance covers temporary lifecycle copies;
  // when both directories share a volume, it is checked, not added twice.
  Result := EdrCheckSpaceDirectory('temporary', ExpandConstant('{tmp}'), FloorBytes, GrowthBytes);
end;
