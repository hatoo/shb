#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

static SSL_CTX *ctx;
static unsigned char *body;
static size_t body_len;
static unsigned long long expected, close_after;
static _Atomic unsigned long long requests, body_bytes, connections, active, clean_eof, bare_eof;
static void fail(const char *message) { perror(message); ERR_print_errors_fp(stderr); exit(1); }
static void check(bool ok, const char *message) { if (!ok) fail(message); }
static void *serve(void *arg) {
    int fd=(int)(intptr_t)arg;
    SSL *ssl=SSL_new(ctx);check(ssl!=NULL,"SSL_new");
    check(SSL_set_fd(ssl,fd)==1,"SSL_set_fd");
    check(SSL_accept(ssl)==1,"SSL_accept");
    check(!SSL_session_reused(ssl),"resumed handshake");
    atomic_fetch_add(&connections,1);
    unsigned char buf[65537];size_t have=0;unsigned long long served=0;
    for (;;) {
        unsigned char *end=NULL;
        while (!(end=memmem(buf,have,"\r\n\r\n",4))) {
            check(have<16384,"oversized header");
            int n=SSL_read(ssl,buf+have,(int)(65536-have));
            if (n<=0) {
                check(have==0,"truncated header");
                int e=SSL_get_error(ssl,n);
                if (e==SSL_ERROR_ZERO_RETURN) atomic_fetch_add(&clean_eof,1);
                else {
                    check(n==0 && (e==SSL_ERROR_SYSCALL||e==SSL_ERROR_SSL),"SSL_read header");
                    atomic_fetch_add(&bare_eof,1);
                }
                goto done;
            }
            have+=(size_t)n;
        }
        size_t head=(size_t)(end-buf)+4;
        buf[head-2]=0;
        check(!strncmp((char*)buf,body_len?"POST / HTTP/1.1\r\n":"GET / HTTP/1.1\r\n",body_len?17:16),"request line");
        char *cl=strcasestr((char*)buf,"\r\ncontent-length:");
        size_t length=cl?(size_t)strtoull(cl+17,NULL,10):0;
        check(length==body_len,"content length");
        bool closing=strcasestr((char*)buf,"\r\nconnection: close")!=NULL || (close_after&&served+1==close_after);
        size_t offset=0,available=have-head;
        check(available<=body_len,"unsolicited pipeline bytes");
        if (available) check(!memcmp(buf+head,body,available),"initial body mismatch");
        offset+=available;
        while (offset<body_len) {
            int n=SSL_read(ssl,buf,(int)(body_len-offset<65536?body_len-offset:65536));
            check(n>0,"truncated body");
            check(!memcmp(buf,body+offset,(size_t)n),"body mismatch");
            offset+=(size_t)n;
        }
        // No success response exists until this entire upload is verified.
        atomic_fetch_add(&body_bytes,offset);atomic_fetch_add(&requests,1);served++;have=0;
        const char *reply=closing?"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc":"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: keep-alive\r\n\r\nabc";
        check(SSL_write(ssl,reply,(int)strlen(reply))==(int)strlen(reply),"SSL_write");
        if (closing) { SSL_shutdown(ssl);goto done; }
    }
done:
    SSL_free(ssl);close(fd);atomic_fetch_sub(&active,1);return NULL;
}
static double seconds(struct timeval t) { return (double)t.tv_sec+t.tv_usec/1e6; }
int main(int argc,char **argv) {
    check(argc==7,"arguments: cert key TLS12/13 request_count body_file close_after");
    signal(SIGPIPE,SIG_IGN);expected=strtoull(argv[4],NULL,10);close_after=strtoull(argv[6],NULL,10);
    FILE *f=fopen(argv[5],"rb");check(f!=NULL,"body file");check(!fseek(f,0,SEEK_END),"seek");
    long size=ftell(f);check(size>=0,"size");body_len=(size_t)size;rewind(f);body=malloc(body_len?body_len:1);
    check(fread(body,1,body_len,f)==body_len,"read body file");fclose(f);
    ctx=SSL_CTX_new(TLS_server_method());check(ctx!=NULL,"SSL_CTX");
    int ver=!strcmp(argv[3],"12")?TLS1_2_VERSION:TLS1_3_VERSION;
    check(SSL_CTX_set_min_proto_version(ctx,ver)&&SSL_CTX_set_max_proto_version(ctx,ver),"TLS version");
    SSL_CTX_set_session_cache_mode(ctx,SSL_SESS_CACHE_OFF);SSL_CTX_set_options(ctx,SSL_OP_NO_TICKET);
    SSL_CTX_set_num_tickets(ctx,0);
    check(SSL_CTX_use_certificate_file(ctx,argv[1],SSL_FILETYPE_PEM)==1,"cert");
    check(SSL_CTX_use_PrivateKey_file(ctx,argv[2],SSL_FILETYPE_PEM)==1,"key");
    int listener=socket(AF_INET,SOCK_STREAM,0);check(listener>=0,"socket");
    struct sockaddr_in addr={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK),.sin_port=0};
    check(!bind(listener,(struct sockaddr*)&addr,sizeof(addr)),"bind");check(!listen(listener,1024),"listen");
    socklen_t addrlen=sizeof(addr);check(!getsockname(listener,(struct sockaddr*)&addr,&addrlen),"getsockname");
    struct rusage before,after;getrusage(RUSAGE_SELF,&before);
    printf("{\"port\":%u}\n",ntohs(addr.sin_port));fflush(stdout);
    while (atomic_load(&requests)<expected || atomic_load(&active)) {
        struct pollfd p={.fd=listener,.events=POLLIN};int ready=poll(&p,1,20);check(ready>=0,"poll");if(!ready)continue;
        int fd=accept(listener,NULL,NULL);check(fd>=0,"accept");int one=1;setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
        struct timeval timeout={.tv_sec=20};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
        atomic_fetch_add(&active,1);pthread_t thread;check(!pthread_create(&thread,NULL,serve,(void*)(intptr_t)fd),"thread");pthread_detach(thread);
    }
    close(listener);getrusage(RUSAGE_SELF,&after);
    check(atomic_load(&requests)==expected,"request count");check(atomic_load(&body_bytes)==expected*body_len,"body byte count");
    printf("{\"requests\":%llu,\"body_bytes\":%llu,\"connections\":%llu,\"clean_eof\":%llu,\"bare_eof\":%llu,\"user_seconds\":%.9f,\"system_seconds\":%.9f}\n",atomic_load(&requests),atomic_load(&body_bytes),atomic_load(&connections),atomic_load(&clean_eof),atomic_load(&bare_eof),seconds(after.ru_utime)-seconds(before.ru_utime),seconds(after.ru_stime)-seconds(before.ru_stime));
    SSL_CTX_free(ctx);free(body);return 0;
}
