#include "canokey.h"
#include <assert.h>
#include <string.h>
int main(void) {
  const uint8_t empty[] = {0x53, 0},
                configured[] = {0x53, 5, 0x80, 3, 0x81, 1, 3};
  const uint8_t partial[] = {0x53, 5, 0x80, 3, 0x81, 1, 2},
                bad[] = {0x53, 2, 0x80, 1};
  cnk_error_v1 error = {0};
  error.struct_size = sizeof(error);
  uint32_t flags = 999;
  assert(cnk_piv_admin_data_flags(bad, sizeof(bad), &flags, &error) ==
         CNK_PROTOCOL_ERROR);
  assert(flags == 999 && error.kind == CNK_ERROR_INVALID_RESPONSE &&
         error.phase == CNK_PHASE_PARSING);
  assert(cnk_piv_admin_data_flags(empty, sizeof(empty), &flags, &error) ==
             CNK_OK &&
         flags == 0 && error.kind == 0);
  assert(cnk_piv_admin_data_flags(configured, sizeof(configured), &flags,
                                  &error) == CNK_OK &&
         flags == 3);
  assert(cnk_piv_admin_data_flags(partial, sizeof(partial), &flags, &error) ==
             CNK_OK &&
         flags == 2);
  uint8_t object[30] = {0x53, 28, 0x88, 26, 0x89, 24}, output[24];
  for (unsigned i = 0; i < 24; ++i)
    object[6 + i] = (uint8_t)i;
  size_t length = 0;
  assert(cnk_piv_printed_management_key_copy(object, sizeof(object), NULL,
                                             &length, &error) == CNK_OK &&
         length == 24);
  memset(output, 0xcc, sizeof(output));
  length = 1;
  assert(cnk_piv_printed_management_key_copy(object, sizeof(object), output,
                                             &length,
                                             &error) == CNK_BUFFER_TOO_SMALL);
  assert(length == 24 && output[0] == 0xcc && output[23] == 0xcc);
  assert(cnk_piv_printed_management_key_copy(object, sizeof(object), output,
                                             &length, &error) == CNK_OK);
  assert(!memcmp(output, object + 6, 24));
  memset(output, 0xcc, sizeof(output));
  object[5] = 23;
  assert(cnk_piv_printed_management_key_copy(object, sizeof(object), output,
                                             &length,
                                             &error) == CNK_PROTOCOL_ERROR);
  assert(output[0] == 0xcc && output[23] == 0xcc);
  return 0;
}
