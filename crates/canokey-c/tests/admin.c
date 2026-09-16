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
    cnk_profile_t *p=profile(); cnk_operation_t *op=NULL; uint32_t step=0;
    uint8_t pin[]={'6','5','4','3','2','1'};
    cnk_admin_request_v1 d={0};d.struct_size=sizeof(d);d.kind=CNK_ADMIN_CONFIGURE;
    d.pin=pin;d.pin_len=sizeof(pin);d.present=5;
    assert(cnk_admin_new(p,&d,NULL,&op,NULL)==CNK_OK);
    cnk_profile_free(p);memset(pin,0,sizeof(pin));memset(&d,0,sizeof(d));
    assert(cnk_operation_start(op,&step,NULL)==CNK_OK);
    const uint8_t select[]={0,0xa4,4,0,5,0xf0,0,0,0,0};expect(op,select,sizeof(select));feed(op,ok,2);
    const uint8_t verify[]={0,0x20,0,0,6,'6','5','4','3','2','1'};expect(op,verify,sizeof(verify));feed(op,ok,2);
    const uint8_t read[]={0,0x42,0,0,0};expect(op,read,sizeof(read));
    const uint8_t config[]={1,0x88,0,1,1,0xff,0x90,0};feed(op,config,sizeof(config));
    const uint8_t led[]={0,0x40,1,0};expect(op,led,sizeof(led));feed(op,ok,2);
    const uint8_t ndef[]={0,0x40,4,0};expect(op,ndef,sizeof(ndef));
    cnk_admin_outcome_v1 result={0};result.struct_size=sizeof(result);
    assert(cnk_operation_admin_outcome(op,&result)==CNK_OK&&result.confirmed_writes==1&&result.reprobe_required==1);
    const uint8_t fail[]={0x69,0x85};assert(cnk_operation_advance(op,fail,2,&step,NULL)==CNK_PROTOCOL_ERROR);
    assert(cnk_operation_admin_outcome(op,&result)==CNK_OK&&result.confirmed_writes==1);
    cnk_operation_free(op);
    p=profile();d.struct_size=sizeof(d);d.kind=CNK_ADMIN_CONFIGURATION;
    assert(cnk_admin_new(p,&d,NULL,&op,NULL)==CNK_OK);cnk_profile_free(p);
    assert(cnk_operation_start(op,&step,NULL)==CNK_OK);feed(op,ok,2);feed(op,config,sizeof(config));
    assert(cnk_operation_result_kind(op,&step)==CNK_OK&&step==CNK_RESULT_ADMIN);
    size_t len=0;assert(cnk_operation_result_copy_bytes(op,NULL,&len)==CNK_OK&&len==6);
    uint8_t output[6]={0};len=5;assert(cnk_operation_result_copy_bytes(op,output,&len)==CNK_BUFFER_TOO_SMALL&&len==6&&output[0]==0);
    assert(cnk_operation_result_copy_bytes(op,output,&len)==CNK_OK&&memcmp(output,config,6)==0);
    cnk_operation_free(op);
    p=profile();d.struct_size=sizeof(d);d.kind=CNK_ADMIN_PASS_SLOTS;
    assert(cnk_admin_new(p,&d,NULL,&op,NULL)==CNK_OK);cnk_profile_free(p);
    assert(cnk_operation_start(op,&step,NULL)==CNK_OK);
    expect(op,select,sizeof(select));feed(op,ok,2);
    const uint8_t slots_read[]={0,0x43,0,0,0};expect(op,slots_read,sizeof(slots_read));
    const uint8_t dump[]={0x02,0x01,0x01,0x03,'a','b','c',0x00,0x90,0};feed(op,dump,sizeof(dump));
    assert(cnk_operation_result_kind(op,&step)==CNK_OK&&step==CNK_RESULT_ADMIN);
    result.value_kind=0;
    assert(cnk_operation_admin_outcome(op,&result)==CNK_OK&&result.value_kind==10);
    len=0;assert(cnk_operation_result_copy_bytes(op,NULL,&len)==CNK_OK&&len==8);
    uint8_t slots_bytes[8]={0};assert(cnk_operation_result_copy_bytes(op,slots_bytes,&len)==CNK_OK&&len==8&&memcmp(slots_bytes,dump,8)==0);
    cnk_operation_free(op);return 0;
}
