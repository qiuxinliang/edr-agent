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
static EdrSecurityXmlTextStatus edr_security_xml_read_data(
    const char *xml, const char *name, char *out, size_t cap,
    size_t *source_length, int *unresolved_entity) {
  char needle_single[160];
  char needle_double[160];
  const char *p;
  const char *end;
  size_t prefix;
  size_t decoded = 0u;

  if (source_length) *source_length = 0u;
  if (unresolved_entity) *unresolved_entity = 0;
  if (!xml || !name || !name[0] || !out || cap == 0u) {
    return EDR_SECURITY_XML_TEXT_INVALID;
  }
  out[0] = '\0';
  (void)snprintf(needle_single, sizeof(needle_single), "<Data Name='%s'", name);
  (void)snprintf(needle_double, sizeof(needle_double), "<Data Name=\"%s\"", name);
  p = strstr(xml, needle_single);
  prefix = strlen(needle_single);
  if (!p) {
    p = strstr(xml, needle_double);
    prefix = strlen(needle_double);
  }
  if (!p) return EDR_SECURITY_XML_TEXT_MISSING;
  p += prefix;
  p += strspn(p, " \t\r\n");
  if (p[0] == '/' && p[1] == '>') return EDR_SECURITY_XML_TEXT_COMPLETE;
  if (*p != '>') return EDR_SECURITY_XML_TEXT_INVALID;
  ++p;
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
      } else if (unresolved_entity) {
        *unresolved_entity = 1;
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

static inline EdrSecurityXmlTextStatus edr_security_xml_get_data_utf8(
    const char *xml, const char *name, char *out, size_t cap, size_t *source_length) {
  return edr_security_xml_read_data(xml, name, out, cap, source_length, NULL);
}

/* Registry keys and value names are identities. ETW1's line sanitizer
 * replaces CR/LF with spaces, so those identities cannot be exact either. */
static inline int edr_security_4657_identity_incomplete(
    const char *xml, const char *name, char *out, size_t cap) {
  int unresolved_entity;
  EdrSecurityXmlTextStatus status = edr_security_xml_read_data(xml, name, out, cap, NULL, &unresolved_entity);
  if (status == EDR_SECURITY_XML_TEXT_TRUNCATED && cap > 1u) {
    /* EvtRender supplied valid UTF-8. Keep every complete scalar in the
     * prefix so a split final character cannot invalidate the entire fact. */
    size_t start = cap - 2u;
    while (start && ((unsigned char)out[start] & 0xc0u) == 0x80u) --start;
    unsigned char lead = (unsigned char)out[start];
    size_t width = lead < 0x80u ? 1u : lead < 0xe0u ? 2u : lead < 0xf0u ? 3u : 4u;
    if (width > cap - 1u - start) out[start] = '\0';
  }
  return status != EDR_SECURITY_XML_TEXT_COMPLETE || unresolved_entity || strpbrk(out, "\r\n") != NULL;
}

#endif
