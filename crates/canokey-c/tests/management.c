#include "canokey.h"
#include <assert.h>
#include <string.h>
static const uint8_t ok[]={0x90,0};
static void feed(cnk_operation_t *op,const uint8_t *r,size_t n) {
    uint32_t step=0; cnk_error_v1 error={0};error.struct_size=sizeof(error);
    assert(cnk_operation_advance(op,r,n,&step,&error)==CNK_OK);
}
static void expect(cnk_operation_t *op,const uint8_t *cmd,size_t n) {
    size_t length=0; assert(cnk_operation_command(op,NULL,&length)==CNK_OK&&length==n);
    uint8_t buffer[128];length=sizeof(buffer);
    assert(cnk_operation_command(op,buffer,&length)==CNK_OK&&length==n);
    assert(memcmp(buffer,cmd,n)==0);
}
static void authenticate(cnk_operation_t *op) {
    uint32_t step=0; assert(cnk_operation_start(op,&step,NULL)==CNK_OK);
    const uint8_t select[]={0,0xa4,4,0,5,0xa0,0,0,3,8};expect(op,select,sizeof(select));
    feed(op,ok,sizeof(ok));
    const uint8_t request[]={0,0x87,0x0a,0x9b,4,0x7c,2,0x80,0};expect(op,request,sizeof(request));
    const uint8_t witness[]={0x7c,18,0x80,16,0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91,0x90,0};
    feed(op,witness,sizeof(witness));
    const uint8_t response[]={0,0x87,0x0a,0x9b,38,0x7c,36,0x80,16,0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x81,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    expect(op,response,sizeof(response));
    const uint8_t proof[]={0x7c,18,0x82,16,0x91,0x62,0x51,0x82,0x1c,0x73,0xa5,0x22,0xc3,0x96,0xd6,0x27,0x38,1,0x96,7,0x90,0};
    feed(op,proof,sizeof(proof));
}
int main(void) {
    cnk_operation_t *probe=NULL;uint32_t step=0;
    assert(cnk_probe_device_new(CNK_PROBE_PIV,NULL,&probe,NULL)==CNK_OK);
    assert(cnk_operation_start(probe,&step,NULL)==CNK_OK);
    feed(probe,ok,sizeof(ok));
    const uint8_t fw[]={'3','.','1','.','0',0x90,0};feed(probe,fw,sizeof(fw));
    const uint8_t absent[]={0x6d,0};feed(probe,absent,sizeof(absent));feed(probe,absent,sizeof(absent));
    feed(probe,ok,sizeof(ok));
    const uint8_t version[]={5,7,0,0x90,0};feed(probe,version,sizeof(version));feed(probe,absent,sizeof(absent));
    cnk_profile_t *profile=NULL;assert(cnk_operation_take_profile(probe,&profile)==CNK_OK);cnk_operation_free(probe);
    uint8_t key[24],challenge[16]={0},pin[]={'1','2','3','4','5','6'};
    for(size_t i=0;i<sizeof(key);++i)key[i]=(uint8_t)i;
    cnk_piv_management_v1 management={sizeof(management),CNK_MANAGEMENT_AES192,CNK_AUTH_MUTUAL,key,sizeof(key),challenge,sizeof(challenge)};
    cnk_piv_access_v1 access={sizeof(access),pin,sizeof(pin),&management};
    cnk_operation_t *auth=NULL,*write=NULL,*remove=NULL,*replace=NULL,*object=NULL;
    management.mode=999;
    assert(cnk_piv_authenticate_management_key_new(profile,&management,NULL,&auth,NULL)==CNK_INVALID_ARGUMENT&&auth==NULL);
    management.mode=CNK_AUTH_MUTUAL;
    assert(cnk_piv_authenticate_management_key_new(profile,&management,NULL,&auth,NULL)==CNK_OK);
    const uint8_t der[]={0x30,0},tag[]={0x5f,0xc1,5};
    assert(cnk_piv_write_certificate_new(profile,0x9a,der,sizeof(der),&access,NULL,&write,NULL)==CNK_OK);
    access.pin=NULL;access.pin_len=0;
    assert(cnk_piv_delete_certificate_new(profile,0x9a,&access,NULL,&remove,NULL)==CNK_OK);
    assert(cnk_piv_set_management_key_new(profile,CNK_MANAGEMENT_AES192,key,sizeof(key),CNK_MANAGEMENT_TOUCH_ALWAYS,&access,NULL,&replace,NULL)==CNK_OK);
    assert(cnk_piv_write_object_new(profile,tag,sizeof(tag),der,sizeof(der),&access,NULL,&object,NULL)==CNK_OK);
    cnk_profile_free(profile);memset(key,0,sizeof(key));memset(pin,0,sizeof(pin));memset(challenge,0xaa,sizeof(challenge));
    cnk_mutation_result_v1 result={sizeof(result),999};
    assert(cnk_operation_mutation_result(write,&result)==CNK_INVALID_STATE&&result.profile_effect==999);
    authenticate(auth);uint32_t kind=0;
    assert(cnk_operation_result_kind(auth,&kind)==CNK_OK&&kind==CNK_RESULT_UNIT);
    assert(cnk_operation_mutation_result(auth,&result)==CNK_RESULT_TYPE_MISMATCH);cnk_operation_free(auth);
    authenticate(write);
    const uint8_t verify[]={0,0x20,0,0x80,8,'1','2','3','4','5','6',0xff,0xff};expect(write,verify,sizeof(verify));feed(write,ok,sizeof(ok));
    const uint8_t put[]={0,0xdb,0x3f,0xff,16,0x5c,3,0x5f,0xc1,5,0x53,9,0x70,2,0x30,0,0x71,1,0,0xfe,0};expect(write,put,sizeof(put));feed(write,ok,sizeof(ok));
    assert(cnk_operation_result_kind(write,&kind)==CNK_OK&&kind==CNK_RESULT_MUTATION);
    assert(cnk_operation_mutation_result(write,&result)==CNK_OK&&result.profile_effect==CNK_PROFILE_UNCHANGED);
    assert(cnk_operation_mutation_result(write,&result)==CNK_OK);cnk_operation_free(write);
    authenticate(remove);const uint8_t del[]={0,0xdb,0x3f,0xff,7,0x5c,3,0x5f,0xc1,5,0x53,0};expect(remove,del,sizeof(del));feed(remove,ok,sizeof(ok));cnk_operation_free(remove);
    authenticate(replace);uint8_t set[32]={0,0xff,0xff,0xfe,27,0x0a,0x9b,24};for(size_t i=0;i<24;++i)set[8+i]=(uint8_t)i;expect(replace,set,sizeof(set));
    const uint8_t failed[]={0x69,0x82};cnk_error_v1 error={0};error.struct_size=sizeof(error);
    assert(cnk_operation_advance(replace,failed,sizeof(failed),&step,&error)==CNK_PROTOCOL_ERROR);
    assert(cnk_operation_mutation_result(replace,&result)==CNK_INVALID_STATE);cnk_operation_free(replace);
    assert(cnk_operation_cancel(object)==CNK_OK);cnk_operation_free(object);
    return 0;
}
