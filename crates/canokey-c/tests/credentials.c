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
 cnk_profile_t *p=profile();cnk_operation_t *ops[4]={0};uint32_t step=0;
 uint8_t old[]={'1','2','3','4','5','6'},new_value[]={'6','5','4','3','2','1'};
 assert(cnk_piv_change_pin_new(p,old,6,new_value,6,NULL,&ops[0],NULL)==CNK_OK);
 assert(cnk_piv_change_puk_new(p,old,6,new_value,6,NULL,&ops[1],NULL)==CNK_OK);
 assert(cnk_piv_unblock_pin_new(p,old,6,new_value,6,NULL,&ops[2],NULL)==CNK_OK);
 assert(cnk_piv_logout_new(p,NULL,&ops[3],NULL)==CNK_OK);
 cnk_profile_free(p);memset(old,0,6);memset(new_value,0,6);
 for(size_t i=0;i<4;++i){
  assert(cnk_operation_start(ops[i],&step,NULL)==CNK_OK);
  const uint8_t select[]={0,0xa4,4,0,5,0xa0,0,0,3,8};expect(ops[i],select,sizeof(select));feed(ops[i],ok,2);
  if(i<3){
   uint8_t command[]={0,0x24,0,0x80,16,'1','2','3','4','5','6',0xff,0xff,'6','5','4','3','2','1',0xff,0xff};
   if(i==1)command[3]=0x81;
   if(i==2)command[1]=0x2c;
   expect(ops[i],command,sizeof(command));
   const uint8_t fail[]={0x63,0xc2};cnk_error_v1 e={0};e.struct_size=sizeof(e);
   assert(cnk_operation_advance(ops[i],fail,2,&step,&e)==CNK_PROTOCOL_ERROR);
   assert(e.reference==(i==0?CNK_REFERENCE_PIN:CNK_REFERENCE_PUK)&&e.retries_remaining==2);
  }else{const uint8_t command[]={0,0x20,0xff,0x80,0};expect(ops[i],command,sizeof(command));feed(ops[i],ok,2);}
  cnk_operation_free(ops[i]);
 }
 return 0;
}
