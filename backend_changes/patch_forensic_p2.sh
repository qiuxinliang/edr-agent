#!/bin/bash
# Patch forensic_p2.go: change repo type + add PostDeepForensic handler

FILE="internal/handler/forensic_p2.go"

# 1. Add "database/sql" to imports (after "encoding/json")
sed -i '' '/"encoding\/json"/a\
	"database/sql"
' "$FILE"

# 2. Change *repo.EndpointsSQL to endpointStore
sed -i '' 's/repo          \*repo\.EndpointsSQL/repo          endpointStore/' "$FILE"

# 3. Append PostDeepForensic handler before the last closing brace or at end
# We'll append it after the dispatchCommand function
cat >> "$FILE" << 'PATCH_END'

type deepForensicRequest struct {
	Scope int `json:"scope"`
}

type deepForensicResponse struct {
	TaskID string `json:"task_id"`
	Status string `json:"status"`
}

func (h *ForensicP2Handler) PostDeepForensic(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		apijson.JSONError(c, http.StatusBadRequest, "INVALID_ARGUMENT", "missing endpoint id")
		return
	}

	if _, err := h.repo.Get(c.Request.Context(), tenantID, id); err == sql.ErrNoRows {
		apijson.JSONError(c, http.StatusNotFound, "NOT_FOUND", "endpoint not found")
		return
	} else if err != nil {
		apijson.JSONError(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	var body deepForensicRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		apijson.JSONError(c, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}

	if body.Scope < 1 || body.Scope > 3 {
		apijson.JSONError(c, http.StatusBadRequest, "INVALID_ARGUMENT", "scope must be 1 (light), 2 (standard), or 3 (full)")
		return
	}

	taskID := fmt.Sprintf("cmd_forensic_deep_%d", time.Now().UnixNano())
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)

	registerResponseTask(responseTaskSnapshot{
		TaskID:     taskID,
		EndpointID: id,
		Action:     "forensic_deep",
		Status:     "queued",
		Progress:   0,
		Scope:      fmt.Sprintf("scope_%d", body.Scope),
		CreatedAt:  createdAt,
		UpdatedAt:  createdAt,
		Message:    fmt.Sprintf("deep forensic collection scope=%d", body.Scope),
	})

	pl, _ := json.Marshal(map[string]int{"scope": body.Scope})
	env := &ingestv1.CommandEnvelope{
		CommandId:      taskID,
		CommandType:    "forensic_deep",
		Payload:        pl,
		IssuedAtUnixMs: time.Now().UnixMilli(),
		IdempotencyKey: taskID,
	}

	if h.cmdBroker != nil && h.cmdBroker.Publish(id, env) {
		log.Printf("[forensic-p2] pushed endpoint=%s id=%s via gRPC subscribe", id, taskID)
	} else if h.cmdHTTPOutbox != nil && h.cmdHTTPOutbox.Enqueue(id, env) {
		log.Printf("[forensic-p2] queued endpoint=%s id=%s via HTTP outbox", id, taskID)
	} else {
		log.Printf("[forensic-p2] no broker/outbox for endpoint=%s id=%s", id, taskID)
	}

	apijson.JSONSuccess(c, deepForensicResponse{
		TaskID: taskID,
		Status: "dispatched",
	})
}
PATCH_END

echo "forensic_p2.go patched"
