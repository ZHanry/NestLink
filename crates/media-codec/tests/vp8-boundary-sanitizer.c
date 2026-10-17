#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int (*callback_fn)(void *, const uint8_t *, size_t, uint64_t, uint32_t);
int nl_vp8_encoder_create(uint32_t,uint32_t,uint32_t,uint32_t,void **);
void nl_vp8_encoder_destroy(void *);
int nl_vp8_encoder_set_bitrate(void *,uint32_t);
int nl_vp8_encode(void *,const uint8_t *,size_t,uint64_t,uint32_t,callback_fn,void *);
int nl_vp8_decoder_create(uint32_t,uint32_t,void **);
void nl_vp8_decoder_destroy(void *);
int nl_vp8_decode(void *,const uint8_t *,size_t,uint8_t *,size_t);
struct packet { uint8_t *bytes; size_t length; uint64_t pts; uint32_t key; };
static int save(void *data,const uint8_t *bytes,size_t length,uint64_t pts,uint32_t key) {
  struct packet *p=data; assert(!p->bytes); assert(length>0 && length<=8*1024*1024);
  p->bytes=malloc(length); assert(p->bytes); memcpy(p->bytes,bytes,length);
  p->length=length; p->pts=pts; p->key=key; return 0;
}
static uint32_t rng=0xa2718293;
static uint8_t random_byte(void) { rng^=rng<<13; rng^=rng>>17; rng^=rng<<5; return (uint8_t)rng; }
int main(void) {
  const uint32_t sizes[][2]={{1,1},{17,19},{32,24},{64,48}};
  const uint32_t rates[]={1,29,120};
  for(size_t size=0;size<4;++size) for(size_t rate=0;rate<3;++rate) {
    uint32_t w=sizes[size][0],h=sizes[size][1];
    size_t bytes=(size_t)w*h+2*((w+1)/2)*((h+1)/2);
    uint8_t *input=malloc(bytes),*output=malloc(bytes+2); assert(input&&output);
    memset(input,128,bytes); memset(output,0xda,bytes+2);
    for(size_t i=0;i<(size_t)w*h;++i) input[i]=(uint8_t)(16+i%220);
    void *encoder=NULL,*decoder=NULL;
    assert(!nl_vp8_encoder_create(w,h,rates[rate],2000,&encoder));
    assert(nl_vp8_encoder_set_bitrate(NULL,1000)!=0);
    assert(nl_vp8_encoder_set_bitrate(encoder,0)!=0);
    assert(nl_vp8_encoder_set_bitrate(encoder,63)!=0);
    assert(nl_vp8_encoder_set_bitrate(encoder,100001)!=0);
    assert(nl_vp8_encoder_set_bitrate(encoder,UINT32_MAX)!=0);
    assert(!nl_vp8_decoder_create(w,h,&decoder));
    struct packet first={0};
    for(uint64_t frame=0;frame<8;++frame) {
      assert(!nl_vp8_encoder_set_bitrate(encoder,frame%2?64:100000));
      struct packet packet={0}; uint64_t pts=(uint64_t)INT64_MAX-7+frame;
      assert(!nl_vp8_encode(encoder,input,bytes,pts,frame==5,save,&packet));
      assert(packet.pts==pts); if(frame==0 || frame==5) assert(packet.key);
      assert(!nl_vp8_decode(decoder,packet.bytes,packet.length,output+1,bytes));
      assert(output[0]==0xda && output[bytes+1]==0xda);
      if(frame==0) first=packet; else free(packet.bytes);
    }
    nl_vp8_encoder_destroy(encoder); nl_vp8_decoder_destroy(decoder);
    for(size_t length=0;length<first.length;++length) {
      decoder=NULL; assert(!nl_vp8_decoder_create(w,h,&decoder));
      int code=nl_vp8_decode(decoder,first.bytes,length,output+1,bytes); (void)code;
      assert(output[0]==0xda && output[bytes+1]==0xda);
      nl_vp8_decoder_destroy(decoder);
    }
    for(unsigned trial=0;trial<256;++trial) {
      size_t length=10+(trial*17)%4096; uint8_t *packet=malloc(length); assert(packet);
      for(size_t i=0;i<length;++i) packet[i]=random_byte();
      if(trial%2) memcpy(packet,first.bytes,first.length<length?first.length:length);
      if(trial%4==1) for(size_t i=10;i<length;++i) packet[i]^=random_byte();
      decoder=NULL; assert(!nl_vp8_decoder_create(w,h,&decoder));
      int code=nl_vp8_decode(decoder,packet,length,output+1,bytes); (void)code;
      assert(output[0]==0xda && output[bytes+1]==0xda);
      nl_vp8_decoder_destroy(decoder); free(packet);
    }
    free(first.bytes); free(input); free(output);
  }
  void *handle=(void *)(uintptr_t)1;
  assert(nl_vp8_encoder_create(8192,8192,30,2000,&handle)!=0 && !handle);
  assert(nl_vp8_decoder_create(0,1,&handle)!=0 && !handle);
  puts("VP8 bridge sanitizer: 96 real frames, 3072 mutated packets, every encoded-prefix truncation passed");
  return 0;
}
