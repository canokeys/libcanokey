#include "canokey.h"
#include <assert.h>
#include <string.h>
int main(void) {
  cnk_operation_t *op = NULL;
  uint32_t step = 0;
  cnk_error_v1 error = {0};
  error.struct_size = sizeof(error);
  assert(cnk_piv_read_configuration_selected_new(NULL, &op, &error) == CNK_OK);
  assert(cnk_operation_start(op, &step, &error) == CNK_OK);
  const uint8_t config[] = {1, 0xe0, 5, 0x16, 0xe1, 0x53, 0x54, 0x90, 0};
  assert(cnk_operation_advance(op, config, sizeof(config), &step, &error) ==
         CNK_OK);
  size_t n = 0;
  assert(cnk_operation_piv_configuration_copy(op, NULL, &n) == CNK_OK &&
         n == 10);
  uint8_t output[10];
  n = sizeof(output);
  assert(cnk_operation_piv_configuration_copy(op, output, &n) == CNK_OK);
  const uint8_t expected[] = {1, 0xe0, 5, 0x16, 0xe1, 0x53, 0, 0x54, 0, 0};
  assert(!memcmp(output, expected, 10));
  cnk_operation_free(op);
  assert(cnk_piv_random_selected_new(3, NULL, &op, &error) == CNK_OK);
  assert(cnk_operation_start(op, &step, &error) == CNK_OK);
  const uint8_t version[] = {6, 0, 0, 0x90, 0}, random[] = {1, 2, 3, 0x90, 0};
  assert(cnk_operation_advance(op, version, sizeof(version), &step, &error) ==
         CNK_OK);
  assert(cnk_operation_advance(op, random, sizeof(random), &step, &error) ==
             CNK_OK &&
         step == CNK_STEP_DONE);
  n = sizeof(output);
  assert(cnk_operation_result_copy_bytes(op, output, &n) == CNK_OK && n == 3);
  assert(!memcmp(output, random, 3));
  cnk_operation_free(op);
  return 0;
}
