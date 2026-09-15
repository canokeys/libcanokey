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
  const uint8_t config[] = {1,    0xe0, 0xd1, 0x16, 0xe1, 0x53,
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
  const uint8_t missing_flags[] = {0x53, 4, 0x80, 2, 0x82, 0};
  uint32_t flags = 0xfeed;
  cnk_error_v1 policy_error = {0};
  policy_error.struct_size = sizeof(policy_error);
  assert(cnk_piv_admin_data_flags(missing_flags, sizeof(missing_flags), &flags,
                                  &policy_error) == CNK_PROTOCOL_ERROR);
  assert(flags == 0xfeed && policy_error.kind == CNK_ERROR_INVALID_RESPONSE &&
         policy_error.phase == CNK_PHASE_PARSING);
  cnk_profile_t *p = profile();
  uint32_t version[3] = {99, 99, 99}, serial = 99;
  assert(cnk_profile_firmware_version(p, version) == CNK_OK &&
         version[0] == 3 && version[1] == 1 && version[2] == 0);
  assert(cnk_profile_serial_u32(p, &serial) == CNK_RESULT_TYPE_MISMATCH &&
         serial == 99);
  size_t model_size = 0;
  assert(cnk_profile_model_copy(p, NULL, &model_size) ==
         CNK_RESULT_TYPE_MISMATCH);
  uint32_t semantic = 999;
  assert(cnk_profile_piv_algorithm_from_wire(p, 0xd1, &semantic) == CNK_OK &&
         semantic == CNK_ALGORITHM_RSA3072);
  assert(cnk_profile_piv_algorithm_from_wire(p, 0x54, &semantic) == CNK_OK &&
         semantic == CNK_ALGORITHM_P521);
  semantic = 999;
  assert(cnk_profile_piv_algorithm_from_wire(p, 5, &semantic) ==
             CNK_INVALID_ARGUMENT &&
         semantic == 999);
  assert(cnk_profile_piv_algorithm_from_wire(p, 0x1d1, &semantic) ==
             CNK_INVALID_ARGUMENT &&
         semantic == 999);
  cnk_error_v1 admission = {0};
  admission.struct_size = sizeof(admission);
  assert(cnk_profile_piv_require_algorithm(p, CNK_ALGORITHM_RSA3072,
                                           &admission) == CNK_OK);
  assert(cnk_profile_piv_require_algorithm(p, CNK_ALGORITHM_P521, &admission) ==
         CNK_OK);
  assert(cnk_profile_piv_require_algorithm(p, CNK_ALGORITHM_RSA1024,
                                           &admission) == CNK_PROTOCOL_ERROR);
  assert(admission.kind == CNK_ERROR_UNSUPPORTED_FEATURE &&
         admission.presence_flags == 0);
  assert(cnk_profile_piv_require_algorithm(p, 0xd1, &admission) ==
         CNK_INVALID_ARGUMENT);
  assert(admission.kind == 0);
  assert(cnk_profile_piv_require_algorithm(NULL, CNK_ALGORITHM_RSA2048, NULL) ==
         CNK_INVALID_ARGUMENT);
  cnk_operation_options_v1 existing = {sizeof(existing), CNK_PIV_USE_EXISTING, 261, 258, 1024*1024, 4096};
  cnk_error_v1 error = {.struct_size = sizeof(error)};
  uint8_t tag[] = {0x5f, 0xc1, 5}, value[] = {0xA5};
  cnk_operation_t *op = NULL;
  assert(cnk_piv_write_object_new(p, tag, sizeof(tag), value,
                                             sizeof(value), NULL, &existing, &op,
                                             &error) == CNK_OK);
  cnk_operation_t *framed = NULL, *read = NULL;
  const uint8_t container[] = {0x53, 1, 0xA5};
  assert(cnk_piv_write_object_container_new(
             p, tag, sizeof(tag), container, sizeof(container), NULL, &existing,
             &framed, &error) == CNK_OK);
  assert(cnk_piv_read_object_container_new(
             p, tag, sizeof(tag), &existing, &read, &error) == CNK_OK);
  cnk_operation_t *name_write = NULL, *name_read = NULL;
  uint8_t name[] = {'K', 0};
  assert(cnk_piv_container_name_validate(name, 1, &error) ==
         CNK_INVALID_ARGUMENT);
  assert(error.kind == CNK_ERROR_INVALID_ARGUMENT);
  assert(cnk_piv_container_name_validate(NULL, 0, &error) == CNK_OK &&
         error.kind == 0);
  assert(cnk_piv_set_container_name_new(
             p, 0xf9, name, sizeof(name), NULL, &existing, &name_write, &error) ==
         CNK_OK);
  assert(cnk_piv_read_container_name_new(
             p, 0xf9, NULL, &existing, &name_read, &error) == CNK_OK);
  memset(name, 0, sizeof(name));
  cnk_operation_t *credential = NULL;
  uint8_t short_pin[] = {'1'};
  assert(cnk_piv_credential_new(
             p, CNK_PIV_CREDENTIAL_VERIFY_PIN, short_pin, 1, NULL, 0,
             &existing, &credential, &error) == CNK_OK);
  short_pin[0] = 0;
  cnk_operation_t *empty_slot = NULL;
  assert(cnk_piv_require_empty_key_slot_new(
             p, 0x9c, &existing, &empty_slot, &error) == CNK_OK);
  // Default selection and explicit reuse share a factory; inputs are copied.
  cnk_operation_t *ordinary = NULL;
  assert(cnk_piv_read_object_new(p, tag, sizeof(tag), NULL, &ordinary, &error) == CNK_OK);
  uint32_t first_step = 0;
  assert(cnk_operation_start(ordinary, &first_step, &error) == CNK_OK);
  uint8_t first_command[32]; size_t first_len = sizeof(first_command);
  assert(cnk_operation_command(ordinary, first_command, &first_len) == CNK_OK && first_command[1] == 0xa4);
  cnk_operation_free(ordinary);
  cnk_operation_options_v1 bad = existing; bad.flags |= 4;
  assert(cnk_piv_read_object_new(p, tag, sizeof(tag), &bad, &ordinary, &error) == CNK_INVALID_ARGUMENT && ordinary == NULL);
  bad = existing; bad.struct_size = 4;
  assert(cnk_piv_read_object_new(p, tag, sizeof(tag), &bad, &ordinary, &error) == CNK_INVALID_ARGUMENT && ordinary == NULL);
  const uint8_t pin[] = "123456";
  cnk_piv_access_v1 auth = {sizeof(auth), pin, 6, NULL};
  assert(cnk_piv_get_metadata_new(p, 0x80, &auth, &existing, &ordinary, &error) == CNK_INVALID_ARGUMENT && ordinary == NULL);
  assert(cnk_probe_device_new(CNK_PROBE_PIV, &existing, &ordinary, &error) == CNK_INVALID_ARGUMENT && ordinary == NULL);
  // All borrowed inputs and the profile can disappear before execution.
  memset(value, 0, sizeof(value));
  memset(tag, 0, sizeof(tag));
  cnk_profile_free(p);
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
  assert(cnk_operation_start(name_write, &step, &error) == CNK_OK);
  const uint8_t expected_name[] = {0, 0xf5, 1, 0xf9, 2, 'K', 0};
  n = sizeof(command);
  assert(cnk_operation_command(name_write, command, &n) == CNK_OK &&
         n == sizeof(expected_name));
  assert(memcmp(command, expected_name, n) == 0);
  assert(cnk_operation_advance(name_write, ok, sizeof(ok), &step, &error) ==
             CNK_OK &&
         step == CNK_STEP_DONE);
  cnk_operation_free(name_write);
  assert(cnk_operation_start(name_read, &step, &error) == CNK_OK);
  const uint8_t absent_name[] = {0x6a, 0x88};
  assert(cnk_operation_advance(name_read, absent_name, sizeof(absent_name),
                               &step, &error) == CNK_PROTOCOL_ERROR);
  assert(error.kind == CNK_ERROR_NOT_FOUND && error.status_word == 0x6a88);
  cnk_operation_free(name_read);
  // Runtime response budgets must not be mislabeled as construction errors.
  cnk_operation_t *limited = NULL;
  const uint8_t oversized[259] = {0};
  assert(cnk_probe_device_new(CNK_PROBE_PIV, NULL, &limited, &error) == CNK_OK);
  assert(cnk_operation_start(limited, &step, &error) == CNK_OK);
  assert(cnk_operation_advance(limited, oversized, sizeof(oversized), &step,
                               &error) == CNK_PROTOCOL_ERROR);
  assert(error.kind == CNK_ERROR_LIMIT_EXCEEDED &&
         error.phase == CNK_PHASE_CONVERSATION);
  cnk_operation_free(limited);
  assert(cnk_operation_start(credential, &step, &error) == CNK_OK);
  const uint8_t expected_verify[] = {0,    0x20, 0,    0x80, 8,    '1', 0xff,
                                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  n = sizeof(command);
  assert(cnk_operation_command(credential, command, &n) == CNK_OK &&
         n == sizeof(expected_verify));
  assert(!memcmp(command, expected_verify, n));
  const uint8_t rejected_pin[] = {0x63, 0xc2};
  assert(cnk_operation_advance(credential, rejected_pin, sizeof(rejected_pin),
                               &step, &error) == CNK_PROTOCOL_ERROR);
  assert(error.kind == CNK_ERROR_AUTHENTICATION_FAILED &&
         error.reference == CNK_REFERENCE_PIN && error.retries_remaining == 2);
  cnk_operation_free(credential);
  cnk_operation_t *selection = NULL;
  assert(cnk_piv_select_application_new(NULL, &selection, &error) == CNK_OK);
  assert(cnk_operation_start(selection, &step, &error) == CNK_OK);
  const uint8_t select_command[] = {0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8, 0};
  n = sizeof(command);
  assert(cnk_operation_command(selection, command, &n) == CNK_OK &&
         n == sizeof(select_command));
  assert(!memcmp(command, select_command, n));
  assert(cnk_operation_advance(selection, ok, sizeof(ok), &step, &error) ==
             CNK_OK &&
         step == CNK_STEP_DONE);
  cnk_operation_free(selection);
  assert(cnk_operation_start(empty_slot, &step, &error) == CNK_OK);
  const uint8_t absent_slot[] = {0x6a, 0x88};
  assert(cnk_operation_advance(empty_slot, absent_slot, sizeof(absent_slot),
                               &step, &error) == CNK_OK &&
         step == CNK_STEP_DONE);
  cnk_operation_free(empty_slot);
  return 0;
}
