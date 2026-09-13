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
    cnk_operation_t *metadata=NULL,*signature=NULL,*generate=NULL,*import=NULL,*config=NULL,*decrypt=NULL,*derive=NULL;
    assert(cnk_piv_get_metadata_new(profile,0x80,NULL,NULL,&metadata,NULL)==CNK_OK);
    uint8_t digest[32]={1},scalar[32]={0},ciphertext[256]={1};scalar[31]=1;
    assert(cnk_piv_sign_new(profile,0x9c,CNK_ALGORITHM_P256,CNK_SIGN_DIGEST,digest,sizeof(digest),NULL,NULL,&signature,NULL)==CNK_OK);
    cnk_piv_key_parameters_v1 params={sizeof(params),0x9c,CNK_ALGORITHM_P256,CNK_KEY_PIN_DEFAULT,CNK_KEY_TOUCH_DEFAULT};
    assert(cnk_piv_generate_key_new(profile,&params,&access,NULL,&generate,NULL)==CNK_OK);
    cnk_bytes_t component={scalar,sizeof(scalar)};
    assert(cnk_piv_import_key_new(profile,&params,&component,1,&access,NULL,&import,NULL)==CNK_OK);
    memset(scalar,0,sizeof(scalar));memset(digest,0,sizeof(digest));
    assert(cnk_piv_read_algorithm_config_new(profile,NULL,NULL,&config,NULL)==CNK_PROTOCOL_ERROR&&config==NULL);
    assert(cnk_piv_decrypt_new(profile,0x9d,CNK_ALGORITHM_RSA2048,ciphertext,sizeof(ciphertext),NULL,NULL,&decrypt,NULL)==CNK_OK);
    const uint8_t invalid_peer[65]={4};
    assert(cnk_piv_derive_new(profile,0x9d,CNK_ALGORITHM_P256,invalid_peer,sizeof(invalid_peer),NULL,NULL,&derive,NULL)==CNK_INVALID_ARGUMENT&&derive==NULL);
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
    assert(cnk_operation_start(metadata,&step,NULL)==CNK_OK);feed(metadata,ok,sizeof(ok));
    const uint8_t meta[]={1,1,0xff,5,1,2,6,2,3,9,0x88,1,0xaa,0x90,0};feed(metadata,meta,sizeof(meta));
    cnk_metadata_v1 md={0};md.struct_size=sizeof(md);
    assert(cnk_operation_metadata(metadata,&md)==CNK_OK&&md.presence_flags==25&&md.is_default==2&&md.retries_total==3&&md.retries_remaining==9);
    size_t length=0;assert(cnk_operation_result_copy_bytes(metadata,NULL,&length)==CNK_OK&&length==sizeof(meta)-2);cnk_operation_free(metadata);
    assert(cnk_operation_start(signature,&step,NULL)==CNK_OK);feed(signature,ok,sizeof(ok));
    uint8_t sign_cmd[43]={0,0x87,0x11,0x9c,38,0x7c,36,0x82,0,0x81,32,1};expect(signature,sign_cmd,sizeof(sign_cmd));
    const uint8_t sig[]={0x7c,10,0x82,8,0x30,6,2,1,1,2,1,2,0x90,0};feed(signature,sig,sizeof(sig));
    assert(cnk_operation_key_algorithm(signature,&kind)==CNK_OK&&kind==CNK_ALGORITHM_P256);
    length=0;assert(cnk_operation_signature_p1363(signature,NULL,&length)==CNK_OK&&length==64);
    uint8_t fixed[64]={0xaa};length=1;assert(cnk_operation_signature_p1363(signature,fixed,&length)==CNK_BUFFER_TOO_SMALL&&fixed[0]==0xaa&&length==64);
    assert(cnk_operation_signature_p1363(signature,fixed,&length)==CNK_OK&&fixed[31]==1&&fixed[63]==2);cnk_operation_free(signature);
    authenticate(generate);const uint8_t gen_cmd[]={0,0x47,0,0x9c,5,0xac,3,0x80,1,0x11};expect(generate,gen_cmd,sizeof(gen_cmd));
    uint8_t public_response[72]={0x7f,0x49,67,0x86,65,4};memset(public_response+6,0x42,64);public_response[70]=0x90;feed(generate,public_response,sizeof(public_response));
    length=0;assert(cnk_operation_public_key_copy(generate,CNK_PUBLIC_SPKI,NULL,&length)==CNK_OK&&length==91);
    assert(cnk_operation_key_algorithm(generate,&kind)==CNK_OK&&kind==CNK_ALGORITHM_P256);
    length=sizeof(fixed);assert(cnk_operation_public_key_copy(generate,CNK_PUBLIC_POINT_OR_RAW,fixed,&length)==CNK_BUFFER_TOO_SMALL&&length==65);cnk_operation_free(generate);
    authenticate(import);uint8_t import_cmd[39]={0,0xfe,0x11,0x9c,34,6,32};import_cmd[38]=1;expect(import,import_cmd,sizeof(import_cmd));feed(import,ok,sizeof(ok));
    assert(cnk_operation_mutation_result(import,&result)==CNK_OK);cnk_operation_free(import);
    assert(cnk_operation_cancel(decrypt)==CNK_OK);cnk_operation_free(decrypt);
    return 0;
}
