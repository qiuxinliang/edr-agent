package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"edr-backend/platform/internal/apijson"
	ingestv1 "edr-backend/platform/internal/edrpb/ingestv1/edr/v1"
	"edr-backend/platform/internal/ingestcommand"
	"edr-backend/platform/internal/repo"

	"github.com/gin-gonic/gin"
)

type endpointStore interface {
	Get(ctx context.Context, tenantID, endpointID string) (*repo.EndpointRow, error)
}

type ShellHandler struct {
	repo          endpointStore
	admin         *repo.AdminSQL
	cmdBroker     *ingestcommand.Broker
	cmdHTTPOutbox *ingestcommand.HTTPOutbox
}

type ShellCommandBroker interface {
	Publish(endpointID string, env interface{}) bool
}

type shellRequest struct {
	Command string `json:"command"`
	Timeout int    `json:"timeout"` // 秒, 默认 30
	Workdir string `json:"workdir,omitempty"`
}

type shellResponse struct {
	TaskID    string `json:"task_id"`
	Status    string `json:"status"`
	Command   string `json:"command"`
	CreatedAt string `json:"created_at"`
}

type shellResultResponse struct {
	TaskID     string `json:"task_id"`
	Status     string `json:"status"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int32  `json:"exit_code"`
	DurationMs int64  `json:"duration_ms"`
	FinishedAt string `json:"finished_at"`
}

type shellOpenRequest struct{}

type shellOpenResponse struct {
	TaskID    string `json:"task_id"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type shellInputRequest struct {
	SessionID string `json:"session_id"`
	Input     string `json:"input"`
}

type shellInputResponse struct {
	TaskID string `json:"task_id"`
	Status string `json:"status"`
}

type shellCloseRequest struct {
	SessionID string `json:"session_id"`
}

type shellCloseResponse struct {
	TaskID string `json:"task_id"`
	Status string `json:"status"`
}

var shellAllowList = []string{
	"whoami", "hostname", "systeminfo", "uname",
	"tasklist", "ps", "top",
	"netstat", "ss", "lsof",
	"dir", "ls", "cat", "type", "find", "grep",
	"net", "sc", "reg", "wmic",
	"ipconfig", "ifconfig", "route", "arp",
	"df", "du", "free", "mount",
	"last", "w", "users",
	"crontab", "schtasks",
	"systemctl", "service",
	"docker", "kubectl",
}

var shellBlockList = []string{
	"rm ", "del ", "erase ", "rmdir ", "rd ",
	"format ", "fdisk ",
	"shutdown", "reboot", "halt", "poweroff", "logoff",
	":(){ :|:& };:", "fork bomb",
	">/dev/", ">/etc/", ">/boot/",
	"chmod 777 /", "chown -R",
	"dd if=", "mkfs.",
}

func NewShellHandler(r *repo.EndpointsSQL, admin *repo.AdminSQL) *ShellHandler {
	return &ShellHandler{repo: r, admin: admin}
}

func (h *ShellHandler) SetCommandBroker(broker *ingestcommand.Broker) {
	h.cmdBroker = broker
}

func (h *ShellHandler) SetCommandHTTPOutbox(outbox *ingestcommand.HTTPOutbox) {
	h.cmdHTTPOutbox = outbox
}

func (h *ShellHandler) tryPublishShellOrSimulate(endpointID, taskID string, env *ingestv1.CommandEnvelope) {
	if h.cmdBroker != nil && env != nil && h.cmdBroker.Publish(endpointID, env) {
		log.Printf("[shell] pushed endpoint=%s id=%s via gRPC subscribe", endpointID, taskID)
		return
	}
	if h.cmdHTTPOutbox != nil && env != nil {
		if h.cmdHTTPOutbox.Enqueue(endpointID, env) {
			log.Printf("[shell] queued endpoint=%s id=%s via HTTP outbox", endpointID, taskID)
			return
		}
	}
	log.Printf("[shell] no broker/outbox, fallback to simulate endpoint=%s id=%s", endpointID, taskID)
	go simulateResponseTask(taskID)
}

func (h *ShellHandler) isShellAllowed(command string) bool {
	lower := strings.ToLower(strings.TrimSpace(command))
	for _, blocked := range shellBlockList {
		if strings.Contains(lower, blocked) {
			return false
		}
	}
	firstWord := strings.Fields(lower)
	if len(firstWord) == 0 {
		return false
	}
	cmd := firstWord[0]
	cmd = strings.TrimPrefix(cmd, "./")
	cmd = strings.TrimPrefix(cmd, ".")
	cmd = strings.TrimPrefix(cmd, "\\")
	for _, allowed := range shellAllowList {
		if cmd == allowed {
			return true
		}
	}
	return false
}

func (h *ShellHandler) PostShell(c *gin.Context) {
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

	var body shellRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		apijson.JSONError(c, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}

	command := strings.TrimSpace(body.Command)
	if command == "" {
		apijson.JSONError(c, http.StatusBadRequest, "INVALID_ARGUMENT", "command is required")
		return
	}
	if len(command) > 2048 {
		apijson.JSONError(c, http.StatusBadRequest, "INVALID_ARGUMENT", "command too long (max 2048)")
		return
	}

	if !h.isShellAllowed(command) {
		apijson.JSONError(c, http.StatusForbidden, "COMMAND_BLOCKED", "command not in allow-list or matched block-list")
		return
	}

	timeout := body.Timeout
	if timeout <= 0 || timeout > 300 {
		timeout = 30
	}

	taskID := fmt.Sprintf("cmd_shell_%d", time.Now().UnixNano())
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)

	registerResponseTask(responseTaskSnapshot{
		TaskID:     taskID,
		EndpointID: id,
		Action:     "shell",
		Status:     "queued",
		Progress:   0,
		Scope:      "shell",
		CreatedAt:  createdAt,
		UpdatedAt:  createdAt,
		Message:    fmt.Sprintf("shell: %s", truncate(command, 120)),
	})

	pl, _ := json.Marshal(map[string]interface{}{"command": command, "timeout_sec": timeout})
	env := &ingestv1.CommandEnvelope{
		CommandId:      taskID,
		CommandType:    "rtr_shell",
		Payload:        pl,
		IssuedAtUnixMs: time.Now().UnixMilli(),
		IdempotencyKey: taskID,
	}
	h.tryPublishShellOrSimulate(id, taskID, env)

	apijson.JSONSuccess(c, shellResponse{
		TaskID:    taskID,
		Status:    "dispatched",
		Command:   command,
		CreatedAt: createdAt,
	})
}

func (h *ShellHandler) GetShellResult(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	id := strings.TrimSpace(c.Param("id"))
	taskID := strings.TrimSpace(c.Param("task_id"))

	if id == "" || taskID == "" {
		apijson.JSONError(c, http.StatusBadRequest, "INVALID_ARGUMENT", "missing endpoint id or task_id")
		return
	}

	if _, err := h.repo.Get(c.Request.Context(), tenantID, id); err == sql.ErrNoRows {
		apijson.JSONError(c, http.StatusNotFound, "NOT_FOUND", "endpoint not found")
		return
	}

	task, ok := getResponseTask(taskID)
	if !ok {
		apijson.JSONError(c, http.StatusNotFound, "NOT_FOUND", "task not found")
		return
	}
	if task.EndpointID != id {
		apijson.JSONError(c, http.StatusNotFound, "NOT_FOUND", "task does not belong to this endpoint")
		return
	}

	out := task.DetailUtf8
	if out == "" {
		out = task.Message
	}
	apijson.JSONSuccess(c, shellResultResponse{
		TaskID:     task.TaskID,
		Status:     task.Status,
		Stdout:     out,
		Stderr:     "",
		ExitCode:   0,
		DurationMs: 0,
		FinishedAt: func() string { if task.FinishedAt != nil { return *task.FinishedAt }; return "" }(),
	})
}

func (h *ShellHandler) PostShellOpen(c *gin.Context) {
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

	taskID := fmt.Sprintf("cmd_shell_open_%d", time.Now().UnixNano())
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)

	registerResponseTask(responseTaskSnapshot{
		TaskID:     taskID,
		EndpointID: id,
		Action:     "shell_open",
		Status:     "queued",
		Progress:   0,
		Scope:      "shell",
		CreatedAt:  createdAt,
		UpdatedAt:  createdAt,
		Message:    "interactive shell open",
	})

	env := &ingestv1.CommandEnvelope{
		CommandId:      taskID,
		CommandType:    "shell_open",
		Payload:        []byte("{}"),
		IssuedAtUnixMs: time.Now().UnixMilli(),
		IdempotencyKey: taskID,
	}
	h.tryPublishShellOrSimulate(id, taskID, env)

	apijson.JSONSuccess(c, shellOpenResponse{
		TaskID:    taskID,
		Status:    "dispatched",
		CreatedAt: createdAt,
	})
}

func (h *ShellHandler) PostShellInput(c *gin.Context) {
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

	var body shellInputRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		apijson.JSONError(c, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}

	body.SessionID = strings.TrimSpace(body.SessionID)
	if body.SessionID == "" {
		apijson.JSONError(c, http.StatusBadRequest, "INVALID_ARGUMENT", "session_id is required")
		return
	}

	body.Input = strings.TrimSpace(body.Input)
	if body.Input == "" {
		apijson.JSONError(c, http.StatusBadRequest, "INVALID_ARGUMENT", "input is required")
		return
	}

	taskID := fmt.Sprintf("cmd_shell_input_%d", time.Now().UnixNano())
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)

	registerResponseTask(responseTaskSnapshot{
		TaskID:     taskID,
		EndpointID: id,
		Action:     "shell_input",
		Status:     "queued",
		Progress:   0,
		Scope:      "shell",
		CreatedAt:  createdAt,
		UpdatedAt:  createdAt,
		Message:    fmt.Sprintf("shell input to session %s", body.SessionID),
	})

	pl, _ := json.Marshal(map[string]string{"session_id": body.SessionID, "input": body.Input})
	env := &ingestv1.CommandEnvelope{
		CommandId:      taskID,
		CommandType:    "shell_input",
		Payload:        pl,
		IssuedAtUnixMs: time.Now().UnixMilli(),
		IdempotencyKey: taskID,
	}
	h.tryPublishShellOrSimulate(id, taskID, env)

	apijson.JSONSuccess(c, shellInputResponse{
		TaskID: taskID,
		Status: "dispatched",
	})
}

func (h *ShellHandler) PostShellClose(c *gin.Context) {
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

	var body shellCloseRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		apijson.JSONError(c, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}

	body.SessionID = strings.TrimSpace(body.SessionID)
	if body.SessionID == "" {
		apijson.JSONError(c, http.StatusBadRequest, "INVALID_ARGUMENT", "session_id is required")
		return
	}

	taskID := fmt.Sprintf("cmd_shell_close_%d", time.Now().UnixNano())
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)

	registerResponseTask(responseTaskSnapshot{
		TaskID:     taskID,
		EndpointID: id,
		Action:     "shell_close",
		Status:     "queued",
		Progress:   0,
		Scope:      "shell",
		CreatedAt:  createdAt,
		UpdatedAt:  createdAt,
		Message:    fmt.Sprintf("close shell session %s", body.SessionID),
	})

	pl, _ := json.Marshal(map[string]string{"session_id": body.SessionID})
	env := &ingestv1.CommandEnvelope{
		CommandId:      taskID,
		CommandType:    "shell_close",
		Payload:        pl,
		IssuedAtUnixMs: time.Now().UnixMilli(),
		IdempotencyKey: taskID,
	}
	h.tryPublishShellOrSimulate(id, taskID, env)

	apijson.JSONSuccess(c, shellCloseResponse{
		TaskID: taskID,
		Status: "dispatched",
	})
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
