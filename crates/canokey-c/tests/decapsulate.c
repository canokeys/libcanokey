#include "canokey.h"
#include <assert.h>
#include <string.h>

static const uint8_t ok[] = {0x90, 0};
static void feed(cnk_operation_t *op, const uint8_t *data, size_t len) {
    uint32_t step = 0;
    assert(cnk_operation_advance(op, data, len, &step, NULL) == CNK_OK);
}
static cnk_profile_t *profile(int modern) {
    cnk_operation_t *op = NULL;
    uint32_t step = 0;
    assert(cnk_probe_device_new(CNK_PROBE_PIV, NULL, &op, NULL) == CNK_OK);
    assert(cnk_operation_start(op, &step, NULL) == CNK_OK);
    feed(op, ok, sizeof(ok));
    const uint8_t fw[] = {'3','.','1','.','0',0x90,0};
    const uint8_t fw4[] = {'4','.','0','.','0',0x90,0};
    feed(op, modern ? fw4 : fw, sizeof(fw));
    const uint8_t absent[] = {0x6d,0};
    feed(op, absent, sizeof(absent)); feed(op, absent, sizeof(absent));
    feed(op, ok, sizeof(ok));
    const uint8_t version[] = {5,7,0,0x90,0}; feed(op, version, sizeof(version));
    const uint8_t config[] = {1,0xe0,5,0x16,0xe1,0x53,0x54,0x55,0x56,0x57,0x90,0};
    const uint8_t config4[] = {1,0xe0,5,0x16,0xe1,0x53,0x54,0x55,0x56,0x57,0xd4,0xd5,0x90,0};
    feed(op, modern ? config4 : config, modern ? sizeof(config4) : sizeof(config));
    cnk_profile_t *result = NULL;
    assert(cnk_operation_take_profile(op, &result) == CNK_OK);
    cnk_operation_free(op);
    return result;
}
static void complete(cnk_operation_t *op, int small) {
    uint32_t step = 0;
    assert(cnk_operation_start(op, &step, NULL) == CNK_OK);
    feed(op, ok, sizeof(ok));
    uint8_t payload[1098] = {0x7c,0x82,4,0x46,0x82,0,0x81,0x82,4,0x40};
    size_t payload_len = small ? 778 : sizeof(payload);
    if(small) {
        payload[2] = 3; payload[3] = 6; payload[8] = 3; payload[9] = 0;
    }
    memset(payload + 10, 0x42, payload_len - 10);
    for(size_t offset = 0; offset < payload_len;) {
        size_t n = payload_len - offset;
        if(n > 255) n = 255;
        int last = offset + n == payload_len;
        uint8_t expected[260] = {last ? 0 : 0x10, 0x87, small ? 0xd5 : 0x57, 0x9d, (uint8_t)n};
        memcpy(expected + 5, payload + offset, n);
        uint8_t actual[260]; size_t length = sizeof(actual);
        assert(cnk_operation_command(op, actual, &length) == CNK_OK && length == n + 5);
        assert(memcmp(actual, expected, length) == 0);
        if(!last) feed(op, ok, sizeof(ok));
        offset += n;
    }
    uint8_t reply[38] = {0x7c,34,0x82,32}; reply[36] = 0x90;
    feed(op, reply, sizeof(reply));
}
int main(void) {
    cnk_profile_t *p = profile(0);
    uint8_t ciphertext[1088]; memset(ciphertext, 0x42, sizeof(ciphertext));
    cnk_operation_t *single = NULL, *batch = NULL;
    assert(cnk_piv_decapsulate_new(p, 0x9d, ciphertext, 1087, NULL, NULL, &single, NULL) == CNK_INVALID_ARGUMENT && single == NULL);
    assert(cnk_piv_decapsulate_new(p, 0x9d, ciphertext, sizeof(ciphertext), NULL, NULL, &single, NULL) == CNK_OK);
    cnk_piv_batch_request_v1 request = {0}; request.struct_size = sizeof(request);
    request.kind = CNK_BATCH_DECAPSULATE; request.reference = 0x9d;
    request.data = ciphertext; request.data_len = sizeof(ciphertext);
    assert(cnk_piv_batch_new(p, &request, 1, NULL, &batch, NULL) == CNK_OK);
    // Extended scalar formats use the same C entry point and copied components.
    const uint32_t algorithms[] = {CNK_ALGORITHM_P521, CNK_ALGORITHM_SECP256K1, CNK_ALGORITHM_SM2};
    uint8_t management_key[24] = {0};
    cnk_piv_management_v1 management = {sizeof(management), CNK_MANAGEMENT_AES192, CNK_AUTH_EXTERNAL, management_key, 24, NULL, 0};
    cnk_piv_access_v1 access = {sizeof(access), NULL, 0, &management};
    for(size_t i = 0; i < 3; ++i) {
        uint8_t scalar[66] = {0}; size_t width = i == 0 ? 66 : 32; scalar[width - 1] = 1;
        cnk_piv_key_parameters_v1 params = {sizeof(params), 0x9c, algorithms[i], 0, 0};
        cnk_bytes_t component = {scalar, width}; cnk_operation_t *import = NULL;
        assert(cnk_piv_import_key_new(p, &params, &component, 1, &access, NULL, &import, NULL) == CNK_OK);
        assert(cnk_operation_cancel(import) == CNK_OK); cnk_operation_free(import);
    }
    cnk_profile_free(p); memset(ciphertext, 0, sizeof(ciphertext)); memset(&request, 0, sizeof(request));
    size_t length = 0;
    assert(cnk_operation_result_copy_bytes(single, NULL, &length) == CNK_INVALID_STATE);
    complete(single, 0); complete(batch, 0);
    uint32_t kind = 0;
    assert(cnk_operation_result_kind(single, &kind) == CNK_OK && kind == CNK_RESULT_OBJECT);
    assert(cnk_operation_result_copy_bytes(single, NULL, &length) == CNK_OK && length == 32);
    uint8_t result[32]; memset(result, 0xaa, sizeof(result)); length = 1;
    assert(cnk_operation_result_copy_bytes(single, result, &length) == CNK_BUFFER_TOO_SMALL && length == 32 && result[0] == 0xaa);
    assert(cnk_operation_result_copy_bytes(single, result, &length) == CNK_OK && result[0] == 0);
    length = 0;
    assert(cnk_operation_batch_item_copy_bytes(batch, 0, NULL, &length) == CNK_OK && length == 32);
    assert(cnk_operation_batch_item_copy_bytes(batch, 0, result, &length) == CNK_OK);
    cnk_operation_free(single); cnk_operation_free(batch);
    for(size_t i = 0; i < sizeof(result); ++i) assert(result[i] == 0);

    p = profile(1);
    cnk_piv_capabilities_v1 caps = {0};
    caps.struct_size = sizeof(caps);
    assert(cnk_profile_piv_capabilities(p, &caps) == CNK_OK);
    assert(caps.algorithms & (1u << CNK_ALGORITHM_MLDSA44));
    assert(caps.algorithms & (1u << CNK_ALGORITHM_MLKEM512));
    cnk_operation_t *sign = NULL;
    assert(cnk_piv_sign_streaming_new(p, 0x9c, CNK_STREAM_MLDSA44, NULL, 0,
                                     NULL, 0, NULL, NULL, &sign, NULL) == CNK_OK);
    assert(cnk_operation_cancel(sign) == CNK_OK);
    cnk_operation_free(sign);
    memset(ciphertext, 0x42, sizeof(ciphertext));
    single = NULL;
    assert(cnk_piv_decapsulate_with_algorithm_new(p, 0x9d, CNK_ALGORITHM_MLKEM512,
            ciphertext, sizeof(ciphertext), NULL, NULL, &single, NULL) == CNK_INVALID_ARGUMENT && single == NULL);
    assert(cnk_piv_decapsulate_with_algorithm_new(p, 0x9d, CNK_ALGORITHM_MLKEM512,
            ciphertext, 768, NULL, NULL, &single, NULL) == CNK_OK);
    request.struct_size = sizeof(request);
    request.kind = CNK_BATCH_DECAPSULATE_WITH_ALGORITHM;
    request.reference = 0x9d;
    request.algorithm = CNK_ALGORITHM_MLKEM512;
    request.data = ciphertext;
    request.data_len = 768;
    assert(cnk_piv_batch_new(p, &request, 1, NULL, &batch, NULL) == CNK_OK);
    cnk_profile_free(p);
    memset(ciphertext, 0, sizeof(ciphertext));
    complete(single, 1);
    complete(batch, 1);
    length = 0;
    assert(cnk_operation_result_copy_bytes(single, NULL, &length) == CNK_OK && length == 32);
    length = sizeof(result);
    assert(cnk_operation_batch_item_copy_bytes(batch, 0, result, &length) == CNK_OK && length == 32);
    cnk_operation_free(single);
    cnk_operation_free(batch);
    return 0;
}
