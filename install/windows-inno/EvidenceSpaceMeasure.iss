#define EdrPreflightDllBytes 0
; The [Files] Source expression is the only file list. Return it unchanged and
; count the same source files before compression, including conditional entries.
; Recursive inputs currently use '*'; flat inputs may use any Windows mask.
; A directory stack bounds traversal and avoids recursion once per file.
#define EdrExpandedBytes 0
#define EdrMeasureDepth 0
#define EdrMeasureMask ""
#define EdrMeasureRecursive False
#define EdrMeasureExclude ""
#define EdrMeasureName ""
#define EdrMeasureFileBytes 0
#dim EdrMeasureDirs[64]
#dim EdrMeasureHandles[64]
#dim EdrMeasureResults[64]

#sub EdrMeasureEntry
  #expr EdrMeasureName = FindGetFileName(EdrMeasureHandles[EdrMeasureDepth])
  #if EdrMeasureName != "." && EdrMeasureName != ".."
    #if DirExists(EdrMeasureDirs[EdrMeasureDepth] + EdrMeasureName)
      #if EdrMeasureRecursive
        #if EdrMeasureDepth >= 63
          #error "Evidence space accounting: source directory nesting exceeds 64"
        #endif
        #expr EdrMeasureDirs[EdrMeasureDepth + 1] = EdrMeasureDirs[EdrMeasureDepth] + EdrMeasureName + "\"
        #expr EdrMeasureDepth = EdrMeasureDepth + 1
        #expr EdrMeasureDirectory
        #expr EdrMeasureDepth = EdrMeasureDepth - 1
      #endif
    #elif LowerCase(EdrMeasureName) != LowerCase(EdrMeasureExclude)
      #expr EdrMeasureFileBytes = FileSize(EdrMeasureDirs[EdrMeasureDepth] + EdrMeasureName)
      #if EdrMeasureFileBytes < 0 || EdrMeasureFileBytes > 9007199254740991 - EdrExpandedBytes
        #error "Evidence space accounting: unreadable file or expanded source size overflow"
      #endif
      #expr EdrExpandedBytes = EdrExpandedBytes + EdrMeasureFileBytes
    #endif
  #endif
#endsub

#sub EdrMeasureDirectory
  #for {EdrMeasureHandles[EdrMeasureDepth] = EdrMeasureResults[EdrMeasureDepth] = FindFirst(EdrMeasureDirs[EdrMeasureDepth] + EdrMeasureMask, faAnyFile); EdrMeasureResults[EdrMeasureDepth]; EdrMeasureResults[EdrMeasureDepth] = FindNext(EdrMeasureHandles[EdrMeasureDepth])} EdrMeasureEntry
  #if EdrMeasureHandles[EdrMeasureDepth]
    #expr FindClose(EdrMeasureHandles[EdrMeasureDepth])
  #endif
#endsub

#define EdrSizedSource(str Source, int Recursive = False, str ExcludeName = "") \
  Recursive && ExtractFileName(Source) != "*" ? Error("Evidence space accounting: recursive source must use '*'") : 0, \
  Local[0] = (Copy(Source, 2, 1) == ":" || Copy(Source, 1, 2) == "\\") ? Source : AddBackslash(SourcePath) + Source, \
  EdrMeasureDepth = 0, EdrMeasureDirs[0] = ExtractFilePath(Local[0]), \
  EdrMeasureMask = ExtractFileName(Source), EdrMeasureRecursive = Recursive, \
  EdrMeasureExclude = ExcludeName, EdrMeasureDirectory, Source
