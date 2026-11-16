#include "../src/collector/security_event_xml.h"
#include "../src/collector/registry_name_observation.h"
#include <assert.h>
int main(void) {
  const char *xml[] = {"<Data Name='ObjectValueName'/>",
      "<Data Name='ObjectValueName'>(Default)</Data>", "<Event/>",
      "<Data Name='ObjectValueName'>A\nB</Data>",
      "<Data Name='ObjectValueName'>&unknown;</Data>"};
  const uint8_t expected[] = {EDR_REG_NAME_DEFAULT, EDR_REG_NAME_OBSERVED,
      EDR_REG_NAME_UNKNOWN, EDR_REG_NAME_UNKNOWN, EDR_REG_NAME_UNKNOWN};
  char name[512];
  for (unsigned i=0; i<sizeof(expected); ++i) {
    int incomplete=edr_security_4657_identity_incomplete(xml[i],"ObjectValueName",name,sizeof(name));
    assert(edr_registry_captured_name_observation(name,name,!incomplete)==expected[i]);
  }
  assert(edr_registry_captured_name_observation("","",0)==EDR_REG_NAME_UNKNOWN);
  assert(edr_registry_captured_name_observation("A\nB","A B",1)==EDR_REG_NAME_UNKNOWN);
  assert(edr_registry_captured_name_observation("(Default)","(Default)",1)==EDR_REG_NAME_OBSERVED);
  assert(edr_registry_captured_name_observation("","",1)==EDR_REG_NAME_DEFAULT);
  return 0;
}
