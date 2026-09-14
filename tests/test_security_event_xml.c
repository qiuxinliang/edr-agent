#include "../src/collector/security_event_xml.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_long_command_line(void) {
  static const size_t source_len = 8901u;
  static const char open[] = "<Event><EventData><Data Name='CommandLine'>";
  static const char close[] = "</Data></EventData></Event>";
  char out[2048];
  size_t measured = 0u;
  size_t xml_len = sizeof(open) - 1u + source_len + sizeof(close);
  char *xml = (char *)malloc(xml_len);
  if (!xml) return 0;
  memcpy(xml, open, sizeof(open) - 1u);
  memset(xml + sizeof(open) - 1u, 'A', source_len);
  memcpy(xml + sizeof(open) - 1u + source_len, close, sizeof(close));

  EdrSecurityXmlTextStatus status = edr_security_xml_get_data_utf8(
      xml, "CommandLine", out, sizeof(out), &measured);
  free(xml);
  if (status != EDR_SECURITY_XML_TEXT_TRUNCATED || measured != source_len ||
      strlen(out) != sizeof(out) - 1u) {
    fprintf(stderr, "long CommandLine mismatch: status=%d measured=%zu retained=%zu\n",
            (int)status, measured, strlen(out));
    return 0;
  }
  for (size_t i = 0u; i < sizeof(out) - 1u; ++i) {
    if (out[i] != 'A') return 0;
  }
  return 1;
}

static int verify_entities_and_bounds(void) {
  static const char xml[] =
      "<EventData><Data Name=\"CommandLine\">a&amp;b&lt;c&gt;&quot;d&apos;e</Data></EventData>";
  static const char expected[] = "a&b<c>\"d'e";
  char exact[sizeof(expected)];
  char short_out[sizeof(expected) - 1u];
  size_t measured = 0u;
  if (edr_security_xml_get_data_utf8(xml, "CommandLine", exact, sizeof(exact),
                                     &measured) != EDR_SECURITY_XML_TEXT_COMPLETE ||
      measured != sizeof(expected) - 1u || strcmp(exact, expected) != 0) {
    return 0;
  }
  return edr_security_xml_get_data_utf8(xml, "CommandLine", short_out,
                                        sizeof(short_out), &measured) ==
             EDR_SECURITY_XML_TEXT_TRUNCATED &&
         measured == sizeof(expected) - 1u &&
         strlen(short_out) == sizeof(short_out) - 1u;
}

int main(void) {
  return verify_long_command_line() && verify_entities_and_bounds() ? 0 : 1;
}
