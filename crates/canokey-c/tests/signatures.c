#include "canokey.h"
#include <assert.h>
#include <string.h>

static const uint8_t ok[] = {0x90, 0};
static void feed(cnk_operation_t *op, const uint8_t *data, size_t len) {
    uint32_t step = 0;
    assert(cnk_operation_advance(op, data, len, &step, NULL) == CNK_OK);
}
static cnk_profile_t *profile(void) {
    cnk_operation_t *op = NULL;
    uint32_t step = 0;
    assert(cnk_probe_device_new(CNK_PROBE_PIV, NULL, &op, NULL) == CNK_OK);
    assert(cnk_operation_start(op, &step, NULL) == CNK_OK);
    feed(op, ok, sizeof(ok));
    const uint8_t fw[] = {'3','.','1','.','0',0x90,0};
    feed(op, fw, sizeof(fw));
    const uint8_t absent[] = {0x6d,0};
    feed(op, absent, sizeof(absent)); feed(op, absent, sizeof(absent));
    feed(op, ok, sizeof(ok));
    const uint8_t version[] = {5,7,0,0x90,0}; feed(op, version, sizeof(version));
    const uint8_t config[] = {1,0xe0,5,0x16,0xe1,0x53,0x54,0x55,0x56,0x57,0x90,0};
    feed(op, config, sizeof(config));
    cnk_profile_t *result = NULL;
    assert(cnk_operation_take_profile(op, &result) == CNK_OK);
    cnk_operation_free(op);
    return result;
}

static void sign_response(cnk_operation_t *op) {
    uint32_t step = 0;
    assert(cnk_operation_start(op, &step, NULL) == CNK_OK);
    feed(op, ok, sizeof(ok));
    uint8_t reply[70] = {0x7c,66,0x82,64};
    reply[35] = 1; reply[67] = 2; reply[68] = 0x90;
    feed(op, reply, sizeof(reply));
}
int main(void) {
    cnk_profile_t *p = profile();
    uint8_t digest[32] = {1};
    cnk_operation_t *single = NULL, *batch = NULL;
    assert(cnk_piv_sign_new(p, 0x9c, CNK_ALGORITHM_SM2, CNK_SIGN_DIGEST,
        digest, sizeof(digest), NULL, NULL, &single, NULL) == CNK_OK);
    cnk_piv_batch_request_v1 requests[2] = {0};
    requests[0].struct_size = sizeof(requests[0]); requests[0].kind = CNK_BATCH_SIGN;
    requests[0].reference = 0x9c; requests[0].algorithm = CNK_ALGORITHM_SM2;
    requests[0].input_kind = CNK_SIGN_DIGEST; requests[0].data = digest; requests[0].data_len = sizeof(digest);
    requests[1].struct_size = sizeof(requests[1]); requests[1].kind = CNK_BATCH_READ_CERTIFICATE;
    requests[1].reference = 0x9a;
    assert(cnk_piv_batch_new(p, requests, 2, NULL, &batch, NULL) == CNK_OK);
    cnk_profile_free(p);
    uint32_t encoding = 999;
    assert(cnk_operation_signature_encoding(single, &encoding) == CNK_INVALID_STATE && encoding == 999);
    sign_response(single); sign_response(batch);
    uint32_t step = 0;
    const uint8_t missing[] = {0x6a,0x82};
    assert(cnk_operation_advance(batch, missing, sizeof(missing), &step, NULL) == CNK_PROTOCOL_ERROR);
    assert(cnk_operation_signature_encoding(single, &encoding) == CNK_OK && encoding == CNK_SIGNATURE_P1363);
    assert(cnk_operation_batch_item_signature_encoding(batch, 0, &encoding) == CNK_OK && encoding == CNK_SIGNATURE_P1363);
    assert(cnk_operation_batch_item_signature_encoding(batch, 1, &encoding) == CNK_INVALID_ARGUMENT);
    size_t n = 0;
    assert(cnk_operation_result_copy_bytes(single, NULL, &n) == CNK_OK && n == 64);
    assert(cnk_operation_signature_der(single, NULL, &n) == CNK_OK && n == 8);
    uint8_t der[8] = {0xaa}; n = 1;
    assert(cnk_operation_signature_der(single, der, &n) == CNK_BUFFER_TOO_SMALL && n == 8 && der[0] == 0xaa);
    assert(cnk_operation_signature_der(single, der, &n) == CNK_OK);
    const uint8_t expected[] = {0x30,6,2,1,1,2,1,2};
    assert(memcmp(der, expected, sizeof(expected)) == 0);
    n = 0; assert(cnk_operation_batch_item_signature_der(batch, 0, NULL, &n) == CNK_OK && n == 8);
    n = 1; der[0] = 0xaa;
    assert(cnk_operation_batch_item_signature_der(batch, 0, der, &n) == CNK_BUFFER_TOO_SMALL && n == 8 && der[0] == 0xaa);
    assert(cnk_operation_batch_item_signature_der(batch, 0, der, &n) == CNK_OK);
    uint8_t fixed[64]; n = sizeof(fixed);
    assert(cnk_operation_signature_p1363(single, fixed, &n) == CNK_OK && n == 64 && fixed[31] == 1 && fixed[63] == 2);
    assert(cnk_operation_batch_item_signature_p1363(batch, 0, fixed, &n) == CNK_OK);
    cnk_operation_free(single); cnk_operation_free(batch);
    assert(memcmp(der, expected, sizeof(expected)) == 0);
    return 0;
}
