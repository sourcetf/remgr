/* TURN (RFC 5766) allocation probe over UDP.
 *
 *  1. send Allocate without credentials -> expect 401 + REALM/NONCE
 *  2. resend Allocate with USERNAME/REALM/NONCE/REQUESTED-TRANSPORT +
 *     MESSAGE-INTEGRITY (long-term credential, RFC 5389 10.2.2)
 *  3. expect 200 with XOR-RELAYED-ADDRESS and LIFETIME
 *
 * A successful allocation also proves the per-allocation counters that the
 * console reads through Server::get_allocations_info().
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>

#define ATTR_USERNAME 0x0006
#define ATTR_MESSAGE_INTEGRITY 0x0008
#define ATTR_ERROR_CODE 0x0009
#define ATTR_REALM 0x0014
#define ATTR_NONCE 0x0015
#define ATTR_XOR_RELAYED_ADDRESS 0x0016
#define ATTR_REQUESTED_TRANSPORT 0x0019
#define ATTR_LIFETIME 0x000D
#define ATTR_XOR_MAPPED_ADDRESS 0x0020

static const unsigned char MAGIC[4] = {0x21, 0x12, 0xA4, 0x42};

/* TURN credentials are configuration, not source: pass them as arguments or in
 * the environment. They must never be committed — the operator's config
 * (/etc/remgr/config.toml) is deliberately not in this repository, and a relay
 * credential in a public repository is an open relay for everyone who reads it. */
static const char *USER = NULL;
static const char *PASS = NULL;

static void put16(unsigned char *p, unsigned v) {
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)(v & 0xff);
}

static void put32(unsigned char *p, unsigned v) {
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)(v & 0xff);
}

/* append a TURN attribute with 4-byte padding */
static size_t add_attr(unsigned char *m, size_t off, unsigned type,
                       const unsigned char *val, size_t len) {
    put16(m + off, type);
    put16(m + off + 2, (unsigned)len);
    off += 4;
    if (len) memcpy(m + off, val, len);
    off += len;
    while (off % 4) m[off++] = 0;
    return off;
}

static void dump_hex(const char *label, const unsigned char *p, size_t n) {
    printf("%s (%zu bytes): ", label, n);
    for (size_t i = 0; i < n && i < 48; i++) printf("%02x", p[i]);
    printf("\n");
}

/* find an attribute; returns pointer to its value and sets *len */
static const unsigned char *find_attr(const unsigned char *m, size_t mlen,
                                      unsigned type, size_t *len) {
    size_t off = 20;
    while (off + 4 <= mlen) {
        unsigned at = (m[off] << 8) | m[off + 1];
        unsigned al = (m[off + 2] << 8) | m[off + 3];
        if (at == type) {
            *len = al;
            return m + off + 4;
        }
        off += 4 + al + ((4 - (al % 4)) % 4);
    }
    *len = 0;
    return NULL;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    const char *port = argc > 2 ? argv[2] : "3478";
    USER = argc > 3 ? argv[3] : getenv("TURN_USER");
    PASS = argc > 4 ? argv[4] : getenv("TURN_PASS");
    if (USER == NULL || PASS == NULL || *USER == '\0' || *PASS == '\0') {
        fprintf(stderr,
                "usage: %s [host] [port] <user> <password>\n"
                "       (or set TURN_USER and TURN_PASS; the credentials are the ones\n"
                "        configured in [stun_turn].users of /etc/remgr/config.toml)\n",
                argv[0]);
        return 2;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((unsigned short)atoi(port));
    inet_pton(AF_INET, host, &dst.sin_addr);

    unsigned char txid[12];
    for (int i = 0; i < 12; i++) txid[i] = (unsigned char)(0x40 + i);

    /* ---- 1. unauthenticated Allocate -> 401 with REALM/NONCE */
    unsigned char req[512];
    memset(req, 0, sizeof(req));
    put16(req, 0x0003);        /* Allocate, request */
    put16(req + 2, 0);         /* length */
    memcpy(req + 4, MAGIC, 4);
    memcpy(req + 8, txid, 12);
    size_t off = 20;
    unsigned char proto[4] = {17, 0, 0, 0};   /* REQUESTED-TRANSPORT = UDP */
    off = add_attr(req, off, ATTR_REQUESTED_TRANSPORT, proto, 4);
    put16(req + 2, (unsigned)(off - 20));

    if (sendto(fd, req, off, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        printf("sendto: %s\n", strerror(errno));
        return 1;
    }
    printf("sent unauthenticated Allocate (%zu bytes)\n", off);

    unsigned char buf[1500];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n < 20) { printf("no response (%zd)\n", n); return 1; }
    printf("response type = 0x%04x (expect 0x0113 = 401)\n",
           (buf[0] << 8) | buf[1]);

    size_t realm_len = 0, nonce_len = 0;
    const unsigned char *realm = find_attr(buf, (size_t)n, ATTR_REALM, &realm_len);
    const unsigned char *nonce = find_attr(buf, (size_t)n, ATTR_NONCE, &nonce_len);
    if (!realm || !nonce) { printf("missing REALM/NONCE\n"); return 1; }
    printf("REALM = %.*s\n", (int)realm_len, realm);
    printf("NONCE = %.*s\n", (int)nonce_len, nonce);

    /* ---- 2. authenticated Allocate with MESSAGE-INTEGRITY */
    memset(req, 0, sizeof(req));
    put16(req, 0x0003);
    memcpy(req + 4, MAGIC, 4);
    memcpy(req + 8, txid, 12);
    off = 20;
    off = add_attr(req, off, ATTR_REQUESTED_TRANSPORT, proto, 4);
    off = add_attr(req, off, ATTR_USERNAME, (const unsigned char *)USER, strlen(USER));
    off = add_attr(req, off, ATTR_REALM, realm, realm_len);
    off = add_attr(req, off, ATTR_NONCE, nonce, nonce_len);

    /* key = MD5(username ":" realm ":" password) */
    char keybuf[256];
    int klen = snprintf(keybuf, sizeof(keybuf), "%s:%.*s:%s", USER,
                        (int)realm_len, realm, PASS);
    unsigned char key[16];
    MD5((unsigned char *)keybuf, (size_t)klen, key);
    dump_hex("long-term key", key, sizeof(key));

    /* length must include the 24-byte MESSAGE-INTEGRITY attribute */
    put16(req + 2, (unsigned)(off - 20 + 24));
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned maclen = 0;
    HMAC(EVP_sha1(), key, sizeof(key), req, off, mac, &maclen);
    off = add_attr(req, off, ATTR_MESSAGE_INTEGRITY, mac, maclen);
    printf("authenticated Allocate length = %u, total = %zu\n",
           (unsigned)((req[2] << 8) | req[3]), off);

    if (sendto(fd, req, off, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        printf("sendto: %s\n", strerror(errno));
        return 1;
    }
    n = recv(fd, buf, sizeof(buf), 0);
    if (n < 20) { printf("no response to authenticated Allocate (%zd)\n", n); return 1; }

    unsigned rtype = (buf[0] << 8) | buf[1];
    printf("response type = 0x%04x (expect 0x0103 = Allocate success)\n", rtype);
    if (rtype != 0x0103) {
        size_t elen = 0;
        const unsigned char *ec = find_attr(buf, (size_t)n, ATTR_ERROR_CODE, &elen);
        if (ec && elen >= 4)
            printf("ERROR-CODE = %u%02u reason=%.*s\n", ec[2], ec[3],
                   (int)(elen - 4), ec + 4);
        else
            dump_hex("response", buf, (size_t)n);
        return 1;
    }

    size_t rlen = 0;
    const unsigned char *relayed = find_attr(buf, (size_t)n, ATTR_XOR_RELAYED_ADDRESS, &rlen);
    if (relayed && rlen >= 8) {
        unsigned xport = (relayed[2] << 8) | relayed[3];
        unsigned port = xport ^ 0x2112;
        unsigned ip[4];
        for (int i = 0; i < 4; i++) ip[i] = relayed[4 + i] ^ MAGIC[i];
        printf("XOR-RELAYED-ADDRESS = %u.%u.%u.%u:%u\n", ip[0], ip[1], ip[2], ip[3], port);
    }
    size_t llen = 0;
    const unsigned char *life = find_attr(buf, (size_t)n, ATTR_LIFETIME, &llen);
    if (life && llen >= 4)
        printf("LIFETIME = %u s\n",
               (life[0] << 24) | (life[1] << 16) | (life[2] << 8) | life[3]);

    printf("TURN UDP allocation probe: OK\n");
    /* hold the allocation open so the console shows it as active */
    sleep(20);
    close(fd);
    return 0;
}
