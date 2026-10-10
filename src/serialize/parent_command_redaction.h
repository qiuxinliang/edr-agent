#ifndef EDR_PARENT_COMMAND_REDACTION_H
#define EDR_PARENT_COMMAND_REDACTION_H

/* Wire-only minimization for explicit credential syntax. This parser neither
 * changes the local command fact nor treats ordinary query/argument text as
 * a secret. Replacing value bytes in place cannot grow a bounded wire field. */
static int parent_command_space(unsigned char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}
static int parent_command_key_char(unsigned char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
      (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '%';
}
static int parent_command_hex(unsigned char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
static int parent_command_sensitive_key(const char *s, size_t begin, size_t end) {
  char key[32]; size_t used = 0;
  for (size_t i = begin; i < end; ++i) {
    unsigned char c = (unsigned char)s[i];
    if (c == '%' && i + 2u < end) {
      int a = parent_command_hex((unsigned char)s[i + 1u]);
      int b = parent_command_hex((unsigned char)s[i + 2u]);
      if (a < 0 || b < 0) return 0;
      c = (unsigned char)(a * 16 + b); i += 2u;
    }
    if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + ('a' - 'A'));
    if (c == '_' || c == '-') continue;
    if (used + 1u >= sizeof(key)) return 0;
    key[used++] = (char)c;
  }
  key[used] = 0;
  return !strcmp(key, "password") || !strcmp(key, "passwd") ||
      !strcmp(key, "pwd") || !strcmp(key, "token") ||
      !strcmp(key, "accesstoken") || !strcmp(key, "refreshtoken") ||
      !strcmp(key, "apikey") || !strcmp(key, "clientsecret");
}
static int parent_command_escaped(const char *s, size_t at) {
  size_t slashes = 0, i = at;
  if (at && s[at - 1u] == '`') return 1; /* PowerShell quoted escape. */
  while (i && s[--i] == '\\') ++slashes;
  return (slashes & 1u) != 0;
}
static size_t parent_command_value_end(const char *s, size_t begin, int connection,
                                        char container_quote) {
  char quote = 0;
  size_t i = begin;
  for (; s[i]; ++i) {
    char c = s[i];
    if (!quote && container_quote && c == container_quote &&
        !parent_command_escaped(s, i)) break;
    if ((c == '\'' || c == '"') && !parent_command_escaped(s, i)) {
      if (!quote) quote = c;
      else if (c == quote) {
        if (s[i + 1u] == quote) ++i; /* Doubled quote inside a quoted value. */
        else quote = 0;
      }
      continue;
    }
    if (!quote && (c == ';' || c == '&' || c == '#' ||
        (!connection && parent_command_space((unsigned char)c)))) break;
  }
  return i;
}
static void parent_command_mask_value(char *s, size_t begin, size_t end) {
  if (begin >= end) return;
  /* Preserve only enclosing syntax. An unfinished quoted source still masks
   * every available value byte; truncation is not permission to expose it. */
  if (s[begin] == '\'' || s[begin] == '"') {
    char quote = s[begin++];
    if (end > begin && s[end - 1u] == quote && !parent_command_escaped(s, end - 1u)) --end;
  }
  memset(s + begin, '*', end - begin);
}
static void parent_command_redact_userinfo(char *s) {
  for (size_t i = 0; s[i]; ++i) {
    if (s[i] != ':' || s[i + 1u] != '/' || s[i + 2u] != '/') continue;
    size_t scheme = i;
    while (scheme && ((s[scheme - 1u] >= 'a' && s[scheme - 1u] <= 'z') ||
        (s[scheme - 1u] >= 'A' && s[scheme - 1u] <= 'Z') ||
        (s[scheme - 1u] >= '0' && s[scheme - 1u] <= '9') ||
        s[scheme - 1u] == '+' || s[scheme - 1u] == '-' || s[scheme - 1u] == '.')) --scheme;
    if (scheme == i || !((s[scheme] >= 'a' && s[scheme] <= 'z') ||
        (s[scheme] >= 'A' && s[scheme] <= 'Z'))) continue;
    size_t begin = i + 3u, end = begin, last_at = begin;
    while (s[end] && s[end] != '/' && s[end] != '?' && s[end] != '#' &&
        s[end] != '\'' && s[end] != '"' && !parent_command_space((unsigned char)s[end])) {
      if (s[end] == '@') last_at = end;
      ++end;
    }
    if (last_at > begin) memset(s + begin, '*', last_at - begin);
    i = end ? end - 1u : end;
  }
}
static void parent_command_redact(char *s) {
  if (!s || !s[0]) return;
  parent_command_redact_userinfo(s);
  char container_quote = 0;
  for (size_t i = 0; s[i]; ++i) {
    if ((s[i] == '\'' || s[i] == '"') && !parent_command_escaped(s, i)) {
      if (!container_quote) container_quote = s[i];
      else if (container_quote == s[i]) container_quote = 0;
    }
    char previous = i ? s[i - 1u] : 0;
    if (i && !parent_command_space((unsigned char)previous) &&
        previous != ';' && previous != '?' && previous != '&' &&
        previous != '\'' && previous != '"') continue;
    size_t key = i;
    int option = s[key] == '-';
    if (option) { ++key; if (s[key] == '-') ++key; }
    size_t end = key;
    while (parent_command_key_char((unsigned char)s[end])) ++end;
    if (end == key || !parent_command_sensitive_key(s, key, end)) continue;
    size_t value = end;
    /* A separate argv option token may itself be quoted. Consume its closing
     * quote before looking for a value; keep an enclosing script quote. */
    if (option && (previous == '\'' || previous == '"') &&
        !parent_command_escaped(s, i - 1u) && s[end] == previous &&
        !parent_command_escaped(s, end)) {
      ++value;
      if (container_quote == previous) container_quote = 0;
      i = end;
    }
    size_t separator = value;
    while (parent_command_space((unsigned char)s[value])) ++value;
    int assignment = s[value] == '=' || (option && s[value] == ':');
    if (assignment) {
      ++value;
      while (parent_command_space((unsigned char)s[value])) ++value;
    } else if (!option || value == separator) continue;
    /* A following switch is a missing value, not a credential to redact. */
    if (!assignment && s[value] == '-') continue;
    int connection = !option && (previous == ';' || container_quote != 0);
    size_t stop = parent_command_value_end(s, value, connection,
        s[value] == container_quote ? 0 : container_quote);
    parent_command_mask_value(s, value, stop);
    if (stop > i) i = stop - 1u;
  }
}
#endif
