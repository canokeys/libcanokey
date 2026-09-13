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

static void expect(cnk_operation_t *op,const uint8_t *cmd,size_t n) {
    size_t length=0; assert(cnk_operation_command(op,NULL,&length)==CNK_OK&&length==n);
    uint8_t buffer[128];length=sizeof(buffer);
    assert(cnk_operation_command(op,buffer,&length)==CNK_OK&&length==n);
    assert(memcmp(buffer,cmd,n)==0);
}
int main(void) {
 cnk_profile_t *p=profile();cnk_operation_t *op=NULL;uint32_t step=0;
 uint8_t name[]={'t','e','s','t'};
 cnk_oath_request_v1 d={0};d.struct_size=sizeof(d);d.kind=CNK_OATH_CALCULATE;
 d.name=name;d.name_len=sizeof(name);d.credential_kind=1;d.algorithm=1;d.format=1;
 assert(cnk_oath_new(p,&d,NULL,&op,NULL)==CNK_OK);cnk_profile_free(p);memset(name,0,sizeof(name));
 assert(cnk_operation_start(op,&step,NULL)==CNK_OK);
 const uint8_t select[]={0,0xa4,4,0,7,0xa0,0,0,5,0x27,0x21,1};expect(op,select,sizeof(select));
 const uint8_t selected[]={0x79,3,6,0,0,0x71,8,1,2,3,4,5,6,7,8,0x90,0};feed(op,selected,sizeof(selected));
 const uint8_t calc[]={0,0xa2,0,1,6,0x71,4,'t','e','s','t'};expect(op,calc,sizeof(calc));
 const uint8_t code[]={0x76,5,6,0,0,0,42,0x90,0};feed(op,code,sizeof(code));
 assert(cnk_operation_result_kind(op,&step)==CNK_OK&&step==CNK_RESULT_OATH);
 cnk_oath_info_v1 info={0};info.struct_size=sizeof(info);
 assert(cnk_operation_oath_info(op,0,&info)==CNK_OK&&info.count==1&&info.digits==6&&info.code_kind==1);
 size_t len=0;assert(cnk_operation_oath_copy(op,0,4,NULL,&len)==CNK_OK&&len==6);
 uint8_t output[6]={0};len=5;assert(cnk_operation_oath_copy(op,0,4,output,&len)==CNK_BUFFER_TOO_SMALL&&len==6&&output[0]==0);
 assert(cnk_operation_oath_copy(op,0,4,output,&len)==CNK_OK&&memcmp(output,"000042",6)==0);
 assert(cnk_operation_oath_info(op,1,&info)==CNK_INVALID_ARGUMENT);
 assert(cnk_operation_oath_copy(op,0,2,output,&len)==CNK_RESULT_TYPE_MISMATCH);
 cnk_operation_free(op);return 0;
}
