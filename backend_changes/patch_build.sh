#!/bin/bash
# Patch build.go: add 4 new route registrations

FILE="internal/server/build.go"

# After "hShell.PostShell" route (line ~618), add shell_open/input/close routes
# We'll insert after the GET shell result line
sed -i '' '/v1.GET.*\/shell\/:task_id\/result.*hShell.GetShellResult/a\
	v1.POST("/endpoints/:id/shell/open", middleware.RequireLicenseWriteAllowed(adminRepo, platformService.ActionCommandDispatch), middleware.RequirePermission("endpoint:forensic"), hShell.PostShellOpen)\
	v1.POST("/endpoints/:id/shell/input", middleware.RequireLicenseWriteAllowed(adminRepo, platformService.ActionCommandDispatch), middleware.RequirePermission("endpoint:forensic"), hShell.PostShellInput)\
	v1.POST("/endpoints/:id/shell/close", middleware.RequireLicenseWriteAllowed(adminRepo, platformService.ActionCommandDispatch), middleware.RequirePermission("endpoint:forensic"), hShell.PostShellClose)
' "$FILE"

# After scheduled forensic route (line ~632), add forensic_deep
sed -i '' '/v1.POST.*\/forensic\/schedule.*hForensicP2.PostScheduledForensic/a\
	v1.POST("/endpoints/:id/forensic/deep", middleware.RequireLicenseWriteAllowed(adminRepo, platformService.ActionCommandDispatch), middleware.RequirePermission("endpoint:forensic"), hForensicP2.PostDeepForensic)
' "$FILE"

echo "build.go patched"
