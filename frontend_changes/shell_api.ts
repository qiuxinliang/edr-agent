import { apiClient } from '@/api/client';
import type { ShellRequest, ShellResponse, ShellResultResponse } from '@/api/shell';

export { postShell, getShellResult } from '@/api/shell';
export type { ShellRequest, ShellResponse, ShellResultResponse };

export interface ShellOpenResponse {
  task_id: string;
  status: string;
  created_at: string;
}

export interface ShellInputRequest {
  session_id: string;
  input: string;
}

export interface ShellInputResponse {
  task_id: string;
  status: string;
}

export interface ShellCloseRequest {
  session_id: string;
}

export interface ShellCloseResponse {
  task_id: string;
  status: string;
}

export async function postShellOpen(endpointId: string) {
  return apiClient.post<ShellOpenResponse>(
    `/endpoints/${encodeURIComponent(endpointId)}/shell/open`,
    {},
  );
}

export async function postShellInput(endpointId: string, body: ShellInputRequest) {
  return apiClient.post<ShellInputResponse>(
    `/endpoints/${encodeURIComponent(endpointId)}/shell/input`,
    body,
  );
}

export async function postShellClose(endpointId: string, body: ShellCloseRequest) {
  return apiClient.post<ShellCloseResponse>(
    `/endpoints/${encodeURIComponent(endpointId)}/shell/close`,
    body,
  );
}
