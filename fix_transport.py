import re

# Read the file
with open('src/transport/transport_stub.c', 'r') as f:
    content = f.read()

# Modify queue_push_job to use offline buffer when full
old_queue_push = '''static int queue_push_job(EdrSendJob *j) {
  if (!j) {
    return -1;
  }
#ifdef _WIN32
  EnterCriticalSection(&s_q_mu);
  if (!s_q_run || s_q_len >= s_q_cap) {
    LeaveCriticalSection(&s_q_mu);
    return -1;
  }'''

new_queue_push = '''static int queue_push_job(EdrSendJob *j) {
  if (!j) {
    return -1;
  }
#ifdef _WIN32
  EnterCriticalSection(&s_q_mu);
  if (!s_q_run || s_q_len >= s_q_cap) {
    LeaveCriticalSection(&s_q_mu);
    if (edr_storage_queue_is_open()) {
      int severity = 0;
      if (j->use_http == 0) {
        severity = 1;
      }
      EdrError rc = edr_storage_queue_enqueue(j->batch_id, j->wire, 
                                              j->header_len + j->payload_len, 
                                              0, severity);
      if (rc == EDR_OK) {
        fprintf(stderr, "[transport] queue full, persisted to offline buffer\\n");
        free_send_job(j);
        return 0;
      }
    }
    return -1;
  }'''

content = content.replace(old_queue_push, new_queue_push)

# Also update non-Windows version
old_queue_push_unix = '''#else
  pthread_mutex_lock(&s_q_mu);
  if (!s_q_run || s_q_len >= s_q_cap) {
    pthread_mutex_unlock(&s_q_mu);
    return -1;
  }'''

new_queue_push_unix = '''#else
  pthread_mutex_lock(&s_q_mu);
  if (!s_q_run || s_q_len >= s_q_cap) {
    pthread_mutex_unlock(&s_q_mu);
    if (edr_storage_queue_is_open()) {
      int severity = 0;
      if (j->use_http == 0) {
        severity = 1;
      }
      EdrError rc = edr_storage_queue_enqueue(j->batch_id, j->wire, 
                                              j->header_len + j->payload_len, 
                                              0, severity);
      if (rc == EDR_OK) {
        fprintf(stderr, "[transport] queue full, persisted to offline buffer\\n");
        free_send_job(j);
        return 0;
      }
    }
    return -1;
  }'''

content = content.replace(old_queue_push_unix, new_queue_push_unix)

# Write the file
with open('src/transport/transport_stub.c', 'w') as f:
    f.write(content)

print("Done")