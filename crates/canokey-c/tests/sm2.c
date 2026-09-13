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


static const uint8_t point[]={4,50,196,174,44,31,25,129,25,95,153,4,70,106,57,201,148,143,227,11,191,242,102,11,225,113,90,69,137,51,76,116,199,188,55,54,162,244,246,119,156,89,189,206,227,107,105,33,83,208,169,135,124,198,42,71,64,2,223,50,229,33,57,240,160};

int main(void) {
    cnk_profile_t *p=profile();cnk_operation_t *ops[3]={NULL,NULL,NULL};
    uint8_t peer[65];memcpy(peer,point,65);
    cnk_sm2_input_v1 input={0};input.struct_size=sizeof(input);input.role=CNK_SM2_INITIATOR;input.key_len=16;
    input.peer_static=(cnk_bytes_t){peer,65};input.peer_ephemeral=input.peer_static;
    assert(cnk_piv_agree_sm2_new(p,0x9d,&input,NULL,NULL,&ops[0],NULL)==CNK_OK);
    input.role=CNK_SM2_RESPONDER;assert(cnk_piv_agree_sm2_new(p,0x9d,&input,NULL,NULL,&ops[1],NULL)==CNK_OK);
    cnk_piv_batch_request_v1 r={0};r.struct_size=sizeof(r);r.kind=CNK_BATCH_AGREE_SM2;r.reference=0x9d;r.sm2=&input;
    assert(cnk_piv_batch_new(p,&r,1,NULL,&ops[2],NULL)==CNK_OK);
    cnk_profile_free(p);memset(peer,0,65);memset(&input,0,sizeof(input));
    for(size_t i=0;i<3;++i) {
        uint32_t step=0;assert(cnk_operation_start(ops[i],&step,NULL)==CNK_OK);feed(ops[i],ok,2);
        if(i==0) {
            const uint8_t policy[]={2,2,2,1,0x90,0};feed(ops[i],policy,sizeof(policy));
            uint8_t begin[71]={0x7c,67,0x82,65};memcpy(begin+4,point,65);begin[69]=0x90;feed(ops[i],begin,sizeof(begin));
        }
        uint8_t response[87]={0x7c,85,0x82,65};memcpy(response+4,point,65);response[69]=0x85;response[70]=16;memset(response+71,0x42,16);
        uint8_t final[89];memcpy(final,response,sizeof(response));final[87]=0x90;final[88]=0;
        if(i==0) {uint8_t reply[22]={0x7c,18,0x82,16};memset(reply+4,0x42,16);reply[20]=0x90;feed(ops[i],reply,sizeof(reply));}
        else feed(ops[i],final,sizeof(final));
        size_t n=0;
        if(i==2) {assert(cnk_operation_batch_item_copy_bytes(ops[i],0,NULL,&n)==CNK_OK&&n==16);assert(cnk_operation_batch_item_sm2_ephemeral_copy(ops[i],0,NULL,&n)==CNK_OK&&n==65);}
        else {assert(cnk_operation_result_copy_bytes(ops[i],NULL,&n)==CNK_OK&&n==16);assert(cnk_operation_sm2_ephemeral_copy(ops[i],NULL,&n)==CNK_OK&&n==65);}
        uint8_t copied[65]={0xaa};n=1;
        if(i<2) {assert(cnk_operation_sm2_ephemeral_copy(ops[i],copied,&n)==CNK_BUFFER_TOO_SMALL&&n==65&&copied[0]==0xaa);assert(cnk_operation_sm2_ephemeral_copy(ops[i],copied,&n)==CNK_OK);}
        else {n=65;assert(cnk_operation_batch_item_sm2_ephemeral_copy(ops[i],0,copied,&n)==CNK_OK);}
        assert(memcmp(copied,point,65)==0);cnk_operation_free(ops[i]);
    }
    return 0;
}
