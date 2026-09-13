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
 uint8_t password[]={'8','7','6','5','4','3','2','1'};
 cnk_openpgp_access_v1 access={sizeof(access),0x83,{password,sizeof(password)}};
 cnk_openpgp_request_v1 d={0};d.struct_size=sizeof(d);d.kind=CNK_OPENPGP_WRITE_DATA;
 d.tag=8;d.slot=2;d.value=2;
 assert(cnk_openpgp_new(p,&d,&access,NULL,&op,NULL)==CNK_OK);
 cnk_profile_free(p);memset(password,0,sizeof(password));memset(&d,0,sizeof(d));
 assert(cnk_operation_start(op,&step,NULL)==CNK_OK);
 const uint8_t select[]={0,0xa4,4,0,6,0xd2,0x76,0,1,0x24,1};expect(op,select,sizeof(select));feed(op,ok,2);
 const uint8_t verify[]={0,0x20,0,0x83,8,'8','7','6','5','4','3','2','1'};expect(op,verify,sizeof(verify));feed(op,ok,2);
 const uint8_t touch[]={0,0xda,0,0xd7,2,2,0x20};expect(op,touch,sizeof(touch));feed(op,ok,2);
 assert(cnk_operation_result_kind(op,&step)==CNK_OK&&step==CNK_RESULT_OPENPGP);
 assert(cnk_operation_openpgp_kind(op,&step)==CNK_OK&&step==2);cnk_operation_free(op);
 p=profile();d.struct_size=sizeof(d);d.kind=CNK_OPENPGP_READ_PUBLIC_KEY;d.slot=1;
 assert(cnk_openpgp_new(p,&d,NULL,NULL,&op,NULL)==CNK_OK);cnk_profile_free(p);
 assert(cnk_operation_start(op,&step,NULL)==CNK_OK);feed(op,ok,2);
 const uint8_t app[]={0x6e,14,0x73,12,0xc1,10,0x16,0x2b,6,1,4,1,0xda,0x47,15,1,0x90,0};feed(op,app,sizeof(app));
 const uint8_t read[]={0,0x47,0x81,0,2,0xb6,0};expect(op,read,sizeof(read));
 uint8_t public_key[39]={0x7f,0x49,34,0x86,32};memset(public_key+5,42,32);public_key[37]=0x90;feed(op,public_key,sizeof(public_key));
 size_t len=0;assert(cnk_operation_public_key_copy(op,CNK_PUBLIC_SPKI,NULL,&len)==CNK_OK&&len==44);
 assert(cnk_operation_key_algorithm(op,&step)==CNK_OK&&step==CNK_ALGORITHM_ED25519);cnk_operation_free(op);
 p=profile();memset(&d,0,sizeof(d));d.struct_size=sizeof(d);d.kind=CNK_OPENPGP_PIN_STATUS;d.reference=0x82;
 assert(cnk_openpgp_new(p,&d,NULL,NULL,&op,NULL)==CNK_OK);cnk_profile_free(p);
 assert(cnk_operation_start(op,&step,NULL)==CNK_OK);feed(op,ok,2);const uint8_t retry[]={0x63,0xc3};feed(op,retry,sizeof(retry));
 cnk_pin_status_v1 status={0};status.struct_size=sizeof(status);assert(cnk_operation_pin_status(op,&status)==CNK_OK&&status.remaining==3&&status.verified==0);cnk_operation_free(op);return 0;
}
