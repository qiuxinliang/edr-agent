import re

# Read the file
with open('src/storage/queue_sqlite.c', 'r') as f:
    content = f.read()

# 1. Add severity column to table schema
old_schema = '''  const char *schema =
      "CREATE TABLE IF NOT EXISTS event_queue ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "batch_id TEXT NOT NULL UNIQUE,"
      "payload BLOB NOT NULL,"
      "created_at INTEGER NOT NULL,"
      "compressed INTEGER NOT NULL DEFAULT 0,"
      "retry_count INTEGER NOT NULL DEFAULT 0,"
      "status TEXT NOT NULL DEFAULT 'pending'"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_event_queue_status ON event_queue(status, created_at);";'''

new_schema = '''  const char *schema =
      "CREATE TABLE IF NOT EXISTS event_queue ("
      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "batch_id TEXT NOT NULL UNIQUE,"
      "payload BLOB NOT NULL,"
      "created_at INTEGER NOT NULL,"
      "compressed INTEGER NOT NULL DEFAULT 0,"
      "retry_count INTEGER NOT NULL DEFAULT 0,"
      "status TEXT NOT NULL DEFAULT 'pending',"
      "severity INTEGER NOT NULL DEFAULT 0"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_event_queue_status ON event_queue(status, created_at);"
      "CREATE INDEX IF NOT EXISTS idx_event_queue_severity ON event_queue(severity, created_at);";'''

content = content.replace(old_schema, new_schema)

# 2. Add function to delete lowest severity oldest entries
trim_func = '''
static void trim_queue_if_full(void) {
  if (s_max_entries == 0 || s_pending < s_max_entries) {
    return;
  }
  
  sqlite3_stmt *st = NULL;
  const char *sql = "DELETE FROM event_queue WHERE id IN ("
                    "SELECT id FROM event_queue WHERE status='pending' "
                    "ORDER BY severity ASC, created_at ASC LIMIT 1);";
  
  if (sqlite3_prepare_v2(s_db, sql, -1, &st, NULL) != SQLITE_OK) {
    return;
  }
  
  int rc = sqlite3_step(st);
  sqlite3_finalize(st);
  
  if (rc == SQLITE_DONE) {
    if (s_pending > 0u) {
      s_pending--;
    }
    fprintf(stderr, "[queue] trimmed oldest low-severity entry, pending=%llu\\n", 
            (unsigned long long)s_pending);
  }
}
'''

# Find where to insert the function (before edr_storage_queue_enqueue)
content = content.replace(
    'EdrError edr_storage_queue_enqueue(const char *batch_id, const uint8_t *payload,',
    trim_func + '\nEdrError edr_storage_queue_enqueue(const char *batch_id, const uint8_t *payload,'
)

# 3. Modify edr_storage_queue_enqueue to check max_entries and call trim
old_enqueue = '''EdrError edr_storage_queue_enqueue(const char *batch_id, const uint8_t *payload,
                                   size_t payload_len, int compressed) {
  if (!s_db || !batch_id || !payload || payload_len == 0) {
    return EDR_ERR_INVALID_ARG;
  }

  if (s_max_db_bytes > 0u) {
#if defined(_WIN32) && defined(_MSC_VER)
    struct __stat64 stbuf;
    if (_stat64(s_path, &stbuf) == 0 && (uint64_t)stbuf.st_size >= s_max_db_bytes) {
      fprintf(stderr, "[queue] 库文件超过 EDR_QUEUE_MAX_DB_MB 上限，拒绝入队\\n");
      return EDR_ERR_QUEUE_FULL;
    }
#else
    struct stat stbuf;
    if (stat(s_path, &stbuf) == 0 && (uint64_t)stbuf.st_size >= s_max_db_bytes) {
      fprintf(stderr, "[queue] 库文件超过 EDR_QUEUE_MAX_DB_MB 上限，拒绝入队\\n");
      return EDR_ERR_QUEUE_FULL;
    }
#endif
  }

  sqlite3_stmt *st = NULL;
  const char *ins =
      "INSERT INTO event_queue(batch_id,payload,created_at,compressed,status) "
      "VALUES(?,?,?,?,'pending');";'''

new_enqueue = '''EdrError edr_storage_queue_enqueue(const char *batch_id, const uint8_t *payload,
                                   size_t payload_len, int compressed, int severity) {
  if (!s_db || !batch_id || !payload || payload_len == 0) {
    return EDR_ERR_INVALID_ARG;
  }

  if (s_max_db_bytes > 0u) {
#if defined(_WIN32) && defined(_MSC_VER)
    struct __stat64 stbuf;
    if (_stat64(s_path, &stbuf) == 0 && (uint64_t)stbuf.st_size >= s_max_db_bytes) {
      fprintf(stderr, "[queue] 库文件超过 EDR_QUEUE_MAX_DB_MB 上限，拒绝入队\\n");
      return EDR_ERR_QUEUE_FULL;
    }
#else
    struct stat stbuf;
    if (stat(s_path, &stbuf) == 0 && (uint64_t)stbuf.st_size >= s_max_db_bytes) {
      fprintf(stderr, "[queue] 库文件超过 EDR_QUEUE_MAX_DB_MB 上限，拒绝入队\\n");
      return EDR_ERR_QUEUE_FULL;
    }
#endif
  }

  if (s_max_entries > 0u && s_pending >= s_max_entries) {
    trim_queue_if_full();
  }

  sqlite3_stmt *st = NULL;
  const char *ins =
      "INSERT INTO event_queue(batch_id,payload,created_at,compressed,status,severity) "
      "VALUES(?,?,?,?,?,?);";'''

content = content.replace(old_enqueue, new_enqueue)

# 4. Update the bind statements to include severity
old_bind = '''  sqlite3_bind_text(st, 1, batch_id, -1, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 2, payload, (int)payload_len, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 3, (sqlite3_int64)now);
  sqlite3_bind_int(st, 4, compressed ? 1 : 0);

  int rc = sqlite3_step(st);'''

new_bind = '''  sqlite3_bind_text(st, 1, batch_id, -1, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 2, payload, (int)payload_len, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 3, (sqlite3_int64)now);
  sqlite3_bind_int(st, 4, compressed ? 1 : 0);
  sqlite3_bind_int(st, 5, severity);

  int rc = sqlite3_step(st);'''

content = content.replace(old_bind, new_bind)

# Write the file
with open('src/storage/queue_sqlite.c', 'w') as f:
    f.write(content)

print("Done")