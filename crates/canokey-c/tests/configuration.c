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
    cnk_profile_t *p=profile();
    uint8_t key[24],challenge[16]={0};for(size_t i=0;i<24;++i)key[i]=(uint8_t)i;
    cnk_piv_management_v1 management={sizeof(management),CNK_MANAGEMENT_AES192,CNK_AUTH_MUTUAL,key,24,challenge,16};
    cnk_piv_access_v1 access={sizeof(access),NULL,0,&management};
    cnk_operation_t *directory=NULL,*name=NULL,*set=NULL,*move=NULL,*del=NULL,*retry=NULL,*config=NULL,*attestation=NULL,*reset=NULL,*batch=NULL;
    assert(cnk_piv_read_metadata_directory_new(p,NULL,NULL,&directory,NULL)==CNK_OK);
    assert(cnk_piv_read_container_name_new(p,0x9c,NULL,NULL,&name,NULL)==CNK_OK);
    uint8_t text[]={'K',0};assert(cnk_piv_set_container_name_new(p,0x9c,text,2,&access,NULL,&set,NULL)==CNK_OK);
    assert(cnk_piv_move_key_new(p,0x9c,0x9d,&access,NULL,&move,NULL)==CNK_OK);
    assert(cnk_piv_delete_key_new(p,0x9c,&access,NULL,&del,NULL)==CNK_OK);
    uint8_t pin[]={'1','2','3','4','5','6'};access.pin=pin;access.pin_len=6;
    assert(cnk_piv_reset_pin_puk_retries_new(p,3,5,&access,NULL,&retry,NULL)==CNK_OK);
    access.pin=NULL;access.pin_len=0;
    uint8_t cfg[]={1,0xe0,5,0x16,0xe1,0x53,0x54,0x55,0x56,0x57};
    assert(cnk_piv_set_algorithm_config_new(p,cfg,sizeof(cfg),&access,NULL,&config,NULL)==CNK_OK);
    assert(cnk_piv_attest_new(p,0x9c,NULL,&attestation,NULL)==CNK_OK);
    assert(cnk_piv_reset_piv_new(p,NULL,&reset,NULL)==CNK_OK);
    cnk_piv_batch_request_v1 requests[2]={0};requests[0].struct_size=sizeof(requests[0]);requests[1].struct_size=sizeof(requests[1]);
    requests[0].kind=CNK_BATCH_READ_DIRECTORY;requests[1].kind=CNK_BATCH_READ_CONTAINER_NAME;requests[1].reference=0x9c;
    assert(cnk_piv_batch_new(p,requests,2,NULL,&batch,NULL)==CNK_OK);
    cnk_profile_free(p);memset(text,0,2);memset(key,0,24);memset(pin,0,6);memset(cfg,0,sizeof(cfg));
    uint32_t step=0;cnk_directory_info_v1 info={sizeof(info),99,99,99};
    assert(cnk_operation_directory_info(directory,&info)==CNK_INVALID_STATE&&info.count==99);
    cnk_operation_t *reads[]={directory,batch};
    const uint8_t response[]={1,1,1,2,12,0x9c,2,0,0,0,0,0x9c,0x80,1,2,3,4,0x90,0};
    for(size_t i=0;i<2;++i) {
        assert(cnk_operation_start(reads[i],&step,NULL)==CNK_OK);feed(reads[i],ok,2);
        const uint8_t cmd[]={0,0xf7,1,0,0};expect(reads[i],cmd,sizeof(cmd));feed(reads[i],response,sizeof(response));
    }
    assert(cnk_operation_directory_info(directory,&info)==CNK_OK&&info.count==2&&info.decoded==1);
    cnk_directory_entry_v1 entry={0};entry.struct_size=sizeof(entry);
    assert(cnk_operation_directory_entry(directory,1,&entry)==CNK_OK&&entry.reference==0x9c&&entry.issues==(CNK_DIRECTORY_DUPLICATE_SLOT|CNK_DIRECTORY_UNKNOWN_FLAGS|CNK_DIRECTORY_KEY_FIELDS_WITHOUT_KEY));
    assert(cnk_operation_batch_item_directory_info(batch,0,&info)==CNK_OK&&info.count==2);
    assert(cnk_operation_batch_item_directory_entry(batch,0,0,&entry)==CNK_OK&&entry.flags==2&&entry.issues==0);
    size_t len=0;assert(cnk_operation_result_copy_bytes(directory,NULL,&len)==CNK_OK&&len==17);
    assert(cnk_operation_start(name,&step,NULL)==CNK_OK);feed(name,ok,2);
    const uint8_t name_reply[]={'K',0,0x90,0};feed(name,name_reply,sizeof(name_reply));feed(batch,name_reply,sizeof(name_reply));
    uint8_t copied[2]={0xaa,0xaa};len=1;
    assert(cnk_operation_result_copy_bytes(name,copied,&len)==CNK_BUFFER_TOO_SMALL&&len==2&&copied[0]==0xaa);
    assert(cnk_operation_result_copy_bytes(name,copied,&len)==CNK_OK&&copied[0]=='K'&&copied[1]==0);
    len=0;assert(cnk_operation_batch_item_copy_bytes(batch,1,NULL,&len)==CNK_OK&&len==2);
    authenticate(set);const uint8_t set_cmd[]={0,0xf5,1,0x9c,2,'K',0};expect(set,set_cmd,sizeof(set_cmd));feed(set,ok,2);
    authenticate(move);const uint8_t move_cmd[]={0,0xf6,0x9d,0x9c};expect(move,move_cmd,4);feed(move,ok,2);
    authenticate(del);const uint8_t del_cmd[]={0,0xf6,0xff,0x9c};expect(del,del_cmd,4);feed(del,ok,2);
    authenticate(retry);const uint8_t verify[]={0,0x20,0,0x80,8,'1','2','3','4','5','6',0xff,0xff};expect(retry,verify,sizeof(verify));feed(retry,ok,2);
    const uint8_t retry_cmd[]={0,0xfa,3,5};expect(retry,retry_cmd,4);feed(retry,ok,2);
    authenticate(config);feed(config,ok,2);cnk_mutation_result_v1 mutation={sizeof(mutation),99};
    assert(cnk_operation_mutation_result(config,&mutation)==CNK_OK&&mutation.profile_effect==CNK_PROFILE_REPROBE_REQUIRED);
    assert(cnk_operation_start(attestation,&step,NULL)==CNK_OK);feed(attestation,ok,2);
    const uint8_t der[]={0x30,0,0x90,0};feed(attestation,der,sizeof(der));
    assert(cnk_operation_start(reset,&step,NULL)==CNK_OK);feed(reset,ok,2);
    const uint8_t blocked[]={0x69,0x82};assert(cnk_operation_advance(reset,blocked,2,&step,NULL)==CNK_PROTOCOL_ERROR);
    cnk_operation_t *ops[]={directory,name,set,move,del,retry,config,attestation,reset,batch};
    for(size_t i=0;i<sizeof(ops)/sizeof(ops[0]);++i)cnk_operation_free(ops[i]);
    return 0;
}
