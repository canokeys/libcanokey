#include "canokey.h"
#include <assert.h>
#include <string.h>
static void feed(cnk_operation_t *op,const uint8_t *reply,size_t n) {
 uint32_t step=0;assert(cnk_operation_advance(op,reply,n,&step,NULL)==CNK_OK);
}
static cnk_profile_t *profile(const char *version) {
 cnk_operation_t *op=NULL;cnk_profile_t *p=NULL;uint32_t step=0;
 const uint8_t ok[]={0x90,0},absent[]={0x6d,0},serial[]={1,2,3,4,0x90,0};
 assert(cnk_probe_device_new(CNK_PROBE_MINIMAL,NULL,&op,NULL)==CNK_OK);
 assert(cnk_operation_start(op,&step,NULL)==CNK_OK);feed(op,ok,2);
 uint8_t reply[32];size_t n=strlen(version);memcpy(reply,version,n);reply[n++]=0x90;reply[n++]=0;
 feed(op,reply,n);feed(op,absent,2);feed(op,serial,sizeof(serial));
 assert(cnk_operation_take_profile(op,&p)==CNK_OK);cnk_operation_free(op);return p;
}
int main(void) {
 const uint8_t ok[]={0x90,0};uint32_t step=0;cnk_operation_t *op=NULL;
 cnk_profile_t *p=profile("1.3");cnk_oath_request_v1 oath={0};oath.struct_size=sizeof(oath);oath.kind=CNK_OATH_SELECT;
 assert(cnk_oath_new(p,&oath,NULL,&op,NULL)==CNK_OK);cnk_profile_free(p);
 assert(cnk_operation_start(op,&step,NULL)==CNK_OK);feed(op,ok,2);
 cnk_oath_info_v1 info={0};info.struct_size=sizeof(info);
 assert(cnk_operation_oath_info(op,0,&info)==CNK_OK&&info.kind==5&&info.flags==1);
 size_t n=0;assert(cnk_operation_oath_copy(op,0,1,NULL,&n)==CNK_OK&&n==0);
 assert(cnk_operation_oath_copy(op,0,5,NULL,&n)==CNK_OK&&n==4);
 uint8_t serial[4];assert(cnk_operation_oath_copy(op,0,5,serial,&n)==CNK_OK&&serial[3]==4);
 cnk_operation_free(op);
 p=profile("1.6.2");cnk_admin_request_v1 admin={0};admin.struct_size=sizeof(admin);admin.kind=CNK_ADMIN_SET_KEYBOARD_RETURN;
 uint8_t pin[]={'6','5','4','3','2','1'};admin.pin=pin;admin.pin_len=6;admin.values=1;
 assert(cnk_admin_new(p,&admin,NULL,&op,NULL)==CNK_OK);memset(pin,0,6);
 assert(cnk_operation_start(op,&step,NULL)==CNK_OK);feed(op,ok,2);feed(op,ok,2);
 uint8_t command[16];n=sizeof(command);assert(cnk_operation_command(op,command,&n)==CNK_OK&&n==5);
 const uint8_t expected[]={0,0x40,6,1,0};assert(memcmp(command,expected,5)==0);feed(op,ok,2);cnk_operation_free(op);
 admin.kind=CNK_ADMIN_CONFIGURATION;admin.values=0;
 assert(cnk_admin_new(p,&admin,NULL,&op,NULL)==CNK_OK);cnk_profile_free(p);
 assert(cnk_operation_start(op,&step,NULL)==CNK_OK);feed(op,ok,2);feed(op,ok,2);
 const uint8_t config[]={1,0,0,1,1,1,0x90,0};feed(op,config,sizeof(config));
 cnk_admin_outcome_v1 out={0};out.struct_size=sizeof(out);assert(cnk_operation_admin_outcome(op,&out)==CNK_OK&&out.value_kind==8);
 n=0;assert(cnk_operation_result_copy_bytes(op,NULL,&n)==CNK_OK&&n==6);cnk_operation_free(op);
 p=profile("3.0.0");admin.kind=CNK_ADMIN_SET_LEGACY_OPENPGP_TOUCH;admin.present=0;admin.values=0;
 assert(cnk_admin_new(p,&admin,NULL,&op,NULL)==CNK_PROTOCOL_ERROR&&op==NULL);cnk_profile_free(p);
 p=profile("2.0.0");cnk_profile_t *enabled=NULL;
 cnk_error_v1 error={0};error.struct_size=1;
 assert(cnk_profile_with_legacy_piv_extensions(p,1,&enabled,&error)==CNK_INVALID_ARGUMENT&&enabled==NULL);
 error.struct_size=sizeof(error);error.presence_flags=3;error.status_word=0x6983;
 assert(cnk_profile_with_legacy_piv_extensions(p,1,&enabled,&error)==CNK_OK&&error.presence_flags==0);
 cnk_profile_free(enabled);enabled=NULL;
 assert(cnk_profile_with_legacy_piv_extensions(p,1,&enabled,NULL)==CNK_OK&&enabled!=NULL);
 cnk_profile_free(p);cnk_profile_free(enabled);
 p=profile("3.1.0");enabled=NULL;
 assert(cnk_profile_with_legacy_piv_extensions(p,1,&enabled,NULL)==CNK_PROTOCOL_ERROR&&enabled==NULL);
 cnk_profile_free(p);
 return 0;
}
