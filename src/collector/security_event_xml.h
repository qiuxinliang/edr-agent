#ifndef EDR_SECURITY_EVENT_XML_H
#define EDR_SECURITY_EVENT_XML_H

#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef enum {
  EDR_SECURITY_XML_TEXT_INVALID = -1,
  EDR_SECURITY_XML_TEXT_MISSING = 0,
  EDR_SECURITY_XML_TEXT_COMPLETE = 1,
  EDR_SECURITY_XML_TEXT_TRUNCATED = 2,
} EdrSecurityXmlTextStatus;

/* Security Event XML is already UTF-8 at this boundary. Decode the five XML
 * named entities while measuring the complete decoded source value. The
 * destination remains bounded and always NUL-terminated; callers must retain
 * TRUNCATED as source provenance instead of treating the prefix as complete. */
static EdrSecurityXmlTextStatus edr_security_xml_get_data_utf8(
    const char *xml, const char *name, char *out, size_t cap,
    size_t *source_length) {
  char needle_single[160];
  char needle_double[160];
  const char *p;
  const char *end;
  size_t prefix;
  size_t decoded = 0u;

  if (source_length) *source_length = 0u;
  if (!xml || !name || !name[0] || !out || cap == 0u) {
    return EDR_SECURITY_XML_TEXT_INVALID;
  }
  out[0] = '\0';
  (void)snprintf(needle_single, sizeof(needle_single), "<Data Name='%s'>", name);
  (void)snprintf(needle_double, sizeof(needle_double), "<Data Name=\"%s\">", name);
  p = strstr(xml, needle_single);
  prefix = strlen(needle_single);
  if (!p) {
    p = strstr(xml, needle_double);
    prefix = strlen(needle_double);
  }
  if (!p) return EDR_SECURITY_XML_TEXT_MISSING;
  p += prefix;
  end = strstr(p, "</Data>");
  if (!end || end < p) return EDR_SECURITY_XML_TEXT_INVALID;

  while (p < end) {
    char c = *p++;
    size_t remaining = (size_t)(end - p);
    if (c == '&') {
      if (remaining >= 4u && memcmp(p, "amp;", 4u) == 0) {
        c = '&'; p += 4u;
      } else if (remaining >= 3u && memcmp(p, "lt;", 3u) == 0) {
        c = '<'; p += 3u;
      } else if (remaining >= 3u && memcmp(p, "gt;", 3u) == 0) {
        c = '>'; p += 3u;
      } else if (remaining >= 5u && memcmp(p, "quot;", 5u) == 0) {
        c = '"'; p += 5u;
      } else if (remaining >= 5u && memcmp(p, "apos;", 5u) == 0) {
        c = '\''; p += 5u;
      }
    }
    if (decoded + 1u < cap) out[decoded] = c;
    decoded++;
  }
  out[decoded < cap ? decoded : cap - 1u] = '\0';
  if (source_length) *source_length = decoded;
  return decoded < cap ? EDR_SECURITY_XML_TEXT_COMPLETE
                       : EDR_SECURITY_XML_TEXT_TRUNCATED;
}

#endif
