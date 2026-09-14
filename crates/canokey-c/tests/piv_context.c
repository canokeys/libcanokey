#include "canokey.h"
#include <assert.h>
#include <string.h>

static cnk_profile_t *profile(void) {
  cnk_operation_t *probe = NULL;
  uint32_t step = 0;
  assert(cnk_probe_device_new(CNK_PROBE_PIV, NULL, &probe, NULL) == CNK_OK);
  assert(cnk_operation_start(probe, &step, NULL) == CNK_OK);
  const uint8_t ok[] = {0x90, 0}, absent[] = {0x6d, 0};
  const uint8_t fw[] = {'3', '.', '1', '.', '0', 0x90, 0};
  const uint8_t version[] = {5, 7, 0, 0x90, 0};
  const uint8_t config[] = {1,    0xe0, 5,    0x16, 0xe1, 0x53,
                            0x54, 0x55, 0x56, 0x57, 0x90, 0};
  const uint8_t *responses[] = {ok, fw, absent, absent, ok, version, config};
  const size_t sizes[] = {sizeof(ok),     sizeof(fw), sizeof(absent),
                          sizeof(absent), sizeof(ok), sizeof(version),
                          sizeof(config)};
  for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
    assert(cnk_operation_advance(probe, responses[i], sizes[i], &step, NULL) ==
           CNK_OK);
  cnk_profile_t *result = NULL;
  assert(cnk_operation_take_profile(probe, &result) == CNK_OK);
  cnk_operation_free(probe);
  return result;
}
int main(void) {
  cnk_profile_t *p = profile();
  cnk_piv_context_t *context = NULL;
  cnk_error_v1 error;
  memset(&error, 0xCC, sizeof(error));
  error.struct_size = sizeof(error) - 1;
  assert(cnk_piv_context_new(p, CNK_PIV_CONTEXT_SELECTED, &context, &error) ==
         CNK_INVALID_ARGUMENT);
  assert(context == NULL && error.kind == 0xCCCCCCCC);
  error.struct_size = sizeof(error);
  assert(cnk_piv_context_new(p, CNK_PIV_CONTEXT_MANAGEMENT_AUTHORIZED, &context,
                             &error) == CNK_OK);
  assert(context != NULL && error.kind == 0 && error.presence_flags == 0);
  cnk_profile_free(p);

  uint8_t tag[] = {0x5f, 0xc1, 5}, value[] = {0xA5};
  cnk_operation_t *op = NULL;
  assert(cnk_piv_write_object_in_context_new(context, tag, sizeof(tag), value,
                                             sizeof(value), NULL, &op,
                                             &error) == CNK_OK);
  cnk_operation_t *framed = NULL, *read = NULL;
  const uint8_t container[] = {0x53, 1, 0xA5};
  assert(cnk_piv_write_object_container_in_context_new(
             context, tag, sizeof(tag), container, sizeof(container), NULL,
             &framed, &error) == CNK_OK);
  assert(cnk_piv_read_object_container_in_context_new(
             context, tag, sizeof(tag), NULL, &read, &error) == CNK_OK);
  // All borrowed inputs and the context can disappear before execution.
  memset(value, 0, sizeof(value));
  memset(tag, 0, sizeof(tag));
  cnk_piv_context_free(context);
  uint32_t step = 0;
  assert(cnk_operation_start(op, &step, &error) == CNK_OK);
  const uint8_t expected[] = {0,    0xdb, 0x3f, 0xff, 8, 0x5c, 3,
                              0x5f, 0xc1, 5,    0x53, 1, 0xA5};
  uint8_t command[32];
  size_t n = sizeof(command);
  assert(cnk_operation_command(op, command, &n) == CNK_OK &&
         n == sizeof(expected));
  assert(memcmp(command, expected, n) == 0);
  const uint8_t ok[] = {0x90, 0};
  assert(cnk_operation_advance(op, ok, sizeof(ok), &step, &error) == CNK_OK &&
         step == CNK_STEP_DONE);
  cnk_operation_free(op);
  assert(cnk_operation_start(framed, &step, &error) == CNK_OK);
  n = sizeof(command);
  assert(cnk_operation_command(framed, command, &n) == CNK_OK &&
         n == sizeof(expected));
  assert(memcmp(command, expected, n) == 0);
  cnk_operation_free(framed);
  assert(cnk_operation_start(read, &step, &error) == CNK_OK);
  const uint8_t object_reply[] = {0x53, 1, 0xA5, 0x90, 0};
  assert(cnk_operation_advance(read, object_reply, sizeof(object_reply), &step,
                               &error) == CNK_OK);
  n = sizeof(command);
  assert(cnk_operation_result_copy_bytes(read, command, &n) == CNK_OK &&
         n == sizeof(container));
  assert(memcmp(command, container, n) == 0);
  cnk_operation_free(read);
  cnk_piv_context_free(NULL);
  return 0;
}
