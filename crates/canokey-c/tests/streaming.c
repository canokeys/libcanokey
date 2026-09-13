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


int main(void) {
    cnk_profile_t *p = profile(); cnk_operation_t *ed = NULL, *sm2 = NULL, *batch = NULL;
    assert(cnk_piv_sign_streaming_new(p,0x9c,CNK_STREAM_ED25519_RANDOMIZED,NULL,0,NULL,0,NULL,NULL,&ed,NULL)==CNK_OK);
    assert(cnk_piv_sign_streaming_new(p,0x9c,CNK_STREAM_SM2,NULL,0,NULL,0,NULL,NULL,&sm2,NULL)==CNK_OK);
    cnk_piv_batch_request_v1 request = {0}; request.struct_size=sizeof(request);
    request.kind=CNK_BATCH_SIGN_STREAMING;request.reference=0x9c;request.input_kind=CNK_STREAM_ED25519_RANDOMIZED;
    assert(cnk_piv_batch_new(p,&request,1,NULL,&batch,NULL)==CNK_OK);
    cnk_profile_free(p);
    cnk_operation_t *ops[]={ed,sm2,batch};
    for(size_t i=0;i<3;++i) {
        uint32_t step=0;assert(cnk_operation_start(ops[i],&step,NULL)==CNK_OK);feed(ops[i],ok,sizeof(ok));
        uint8_t command[32];size_t n=sizeof(command);
        assert(cnk_operation_command(ops[i],command,&n)==CNK_OK);
        if(i==1) {
            const uint8_t prefix[]={0x10,0x87,0x55,0x9c,1,0x7c};
            assert(n==sizeof(prefix)&&memcmp(command,prefix,n)==0);
            feed(ops[i],ok,sizeof(ok));n=sizeof(command);
            assert(cnk_operation_command(ops[i],command,&n)==CNK_OK);
            const uint8_t final[]={0,0x87,0x55,0x9c,5,4,0x82,0,0x81,0};
            assert(n==sizeof(final)&&memcmp(command,final,n)==0);
        } else {
            const uint8_t expected[]={0,0x87,0xff,0x9c,6,0x7c,4,0x82,0,0x81,0};
            assert(n==sizeof(expected)&&memcmp(command,expected,n)==0);
        }
        uint8_t reply[70]={0x7c,66,0x82,64};memset(reply+4,1,64);reply[68]=0x90;feed(ops[i],reply,sizeof(reply));
        n=0;
        if(i==2) assert(cnk_operation_batch_item_copy_bytes(ops[i],0,NULL,&n)==CNK_OK&&n==64);
        else assert(cnk_operation_result_copy_bytes(ops[i],NULL,&n)==CNK_OK&&n==64);
        cnk_operation_free(ops[i]);
    }
    return 0;
}
