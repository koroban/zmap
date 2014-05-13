/*
 * Forge Socket Banner Grab Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "logger.h"

#include <event.h>
#include <event2/bufferevent_ssl.h>

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ulimit.h>

#include "forge_socket.h"

#define MAX_BANNER_LEN 2048
#define MAX_PACKET_LEN 4096
#define BASE64_ALPHABET  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
#define SSH_CLIENT_BANNER "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u1"
#define MSG_KEXINIT 20
#define MSG_KEX_DH_GEX_REQUEST_OLD 30
#define MSG_KEXDH_INIT 30
#define MSG_KEXDH_REPLY 31

struct config {
    int read_timeout;        // how long to wait once connected for the banner (seconds)
    int current_running;
    int max_concurrent;
    struct event_base *base;
    struct bufferevent *stdin_bev;
    int stdin_closed;
    enum {FORMAT_HEX, FORMAT_BASE64, FORMAT_ASCII} format;

    struct stats_st {
        int init_connected_hosts;    // Number of hosts we have even tried to connect to
        int connected_hosts;        // # hosts that picked up
        int conn_timed_out;            // # hosts that timed out during connection
        int read_timed_out;            // # hosts that connected, but sent no data (banner)
        int timed_out;                // # hosts that timed out at all (conn_timed_out+read_timed_out)?
        int completed_hosts;        // # hosts that presented a banner
    } stats;
};


struct state {
    struct config *conf;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t seq_ack;
    enum {CONNECTING, CONNECTED, RCV_SRV_STR, SND_CLT_STR, RCV_KEX_INIT, SND_KEX_DH, RCV_KEX_DH, COMPLETED} state;
    uint32_t packet_len;
    uint32_t recv_len;
};

void send_ssh_banner(struct state *st, struct bufferevent *bev);
size_t _ssh_ns_str(char * buf, char * msg, size_t offset);
size_t _ssh_ns(char * buf, char * msg, size_t offset, size_t len);
size_t _ssh_crc_packet(char * msgbuf, size_t len);
void send_kex_init(struct state *st, struct bufferevent *bev);
void send_kex_dh(struct state *st, struct bufferevent *bev);

void stdin_readcb(struct bufferevent *bev, void *arg);

void print_status(evutil_socket_t fd, short events, void *arg)
{
    struct event *ev;
    struct config *conf = arg;
    struct event_base *base = conf->base;
    struct timeval status_timeout = {1, 0};
    ev = evtimer_new(base, print_status, conf);
    evtimer_add(ev, &status_timeout);
    (void)fd; (void)events;

    log_info("forge-socket", "(%d/%d in use) - Totals: %d inited, %d connected, %d conn timeout, %d read timeout %d completed",
            conf->current_running, conf->max_concurrent,
            conf->stats.init_connected_hosts,
            conf->stats.connected_hosts, conf->stats.conn_timed_out,
            conf->stats.read_timed_out, conf->stats.completed_hosts);
}

void decrement_cur_running(struct state *st)
{
    struct config *conf = st->conf;
    conf->current_running--;
    log_debug("forge-socket", "done, down to %d",
            conf->current_running);
    if (evbuffer_get_length(bufferevent_get_input(conf->stdin_bev)) > 0) {
        stdin_readcb(conf->stdin_bev, conf);
    }
    free(st);

    if (conf->stdin_closed && conf->current_running == 0) {
        // Done
        log_info("forge-socket", "done");
        print_status(0, 0, conf);
        exit(0);
    }

}

void event_cb(struct bufferevent *bev, short events, void *arg)
{
    struct state *st = arg;
    struct config *conf = st->conf;
    struct in_addr addr;
    addr.s_addr = st->src_ip;
    if (events & BEV_EVENT_CONNECTED) {
        log_error("forge-socket", "%s connected - wat?", inet_ntoa(addr));
    } else {
        if (st->state == CONNECTED) {
            // Print out that we just didn't receive data
            printf("%s X\n", inet_ntoa(addr));
            fflush(stdout);
            conf->stats.read_timed_out++;
        } else {
            conf->stats.conn_timed_out++;
        }
        log_debug("forge-socket", "%s bailing..", inet_ntoa(addr));
        bufferevent_free(bev);
        conf->stats.timed_out++;
        decrement_cur_running(st);
    }
}

// Grab these bytes, and close the connection.
// Even if we don't need to read any bytes,
// we have to have this so that libevent thinks we have
// a read event, so that it can timeout TCP connects
// (as a read timeout)
void read_cb(struct bufferevent *bev, void *arg)
{
    struct evbuffer *in = bufferevent_get_input(bev);
    struct state *st = arg;
    size_t len = evbuffer_get_length(in);
    struct in_addr addr;
    addr.s_addr = st->src_ip;

    log_debug("forge-socket", "read_cb for %s", inet_ntoa(addr));

    if (len > MAX_BANNER_LEN) {
        len = MAX_BANNER_LEN;
    }

    if (len > 0) {
        // Grab the banner
        unsigned int i;
        unsigned char *buf = malloc(len+1);

        log_trace("forge-socket", "got %d Bytes", len);

        log_trace("forge-socket", "State: %d", st->state);
        if (st->state == CONNECTED) {
            st->packet_len = 0;
            st->state = RCV_SRV_STR;
        } else if (st->state == SND_CLT_STR) {
            st->state = RCV_KEX_INIT;
        } else if (st->state == SND_KEX_DH) {
            st->state = RCV_KEX_DH;
        }
        log_trace("forge-socket", "State Upd: %d", st->state);

        if (!buf) {
            log_fatal("forge-socket", "cannot alloc %d byte buf", len+1);
            return;
        }
        evbuffer_remove(in, buf, len);

        // Send data
        if (st->state == RCV_SRV_STR) {
            if (buf[len-1] != '\n') {
                st->state = COMPLETED;
            } else {
                send_ssh_banner(st, bev);
                send_kex_init(st, bev);
                st->state = SND_CLT_STR;
                st->recv_len = st->packet_len = 0;
            }
        } else if (st->state == RCV_KEX_INIT) {
            if (st->packet_len == 0) {
                st->packet_len = ntohl(*((uint32_t *) buf)) + 4;
                log_trace("forge-socket", "SSH Packet length: %d", st->packet_len);
                if (st->packet_len > MAX_PACKET_LEN) {
                    log_error("forge-socket", "SSH Packet length is longer than MAX_PACKET_LEN.\n");
                    st->state = COMPLETED;
                }
            }
            st->recv_len = st->recv_len + len;
            if (st->recv_len >= st->packet_len) {
                st->recv_len = st->packet_len = 0;
                st->state = SND_KEX_DH;
                send_kex_dh(st, bev);
            }
        } else if (st->state == RCV_KEX_DH) {
            if (st->packet_len == 0) {
                st->packet_len = ntohl(*((uint32_t *) buf)) + 4;
                log_trace("forge-socket", "SSH Packet length: %d", st->packet_len);
                if (st->packet_len > MAX_PACKET_LEN) {
                    log_error("forge-socket", "SSH Packet length is longer than MAX_PACKET_LEN.\n");
                    st->state = COMPLETED;
                }
            }
            st->recv_len = st->recv_len + len;
            if (st->recv_len >= st->packet_len) {
                st->state = COMPLETED;
                st->conf->stats.completed_hosts++;
            }
        } else {
            st->state = COMPLETED;
            // st->conf->stats.completed_hosts++;
        }

        printf("%s [%d, %d, %d] ", inet_ntoa(addr), st->packet_len, st->recv_len, st->state);

        if (st->conf->format == FORMAT_ASCII) {
            // Ascii
            buf[len] = '\0';
            printf("%s\n", buf);
        } else if (st->conf->format == FORMAT_HEX) {
            // Hex output
            for (i=0; i<len; i++) {
                printf("%02x", buf[i]);
            }
            printf("\n");
        } else if (st->conf->format == FORMAT_BASE64) {
            // Base64
            int i=0;
            char out[4] = {0,0,0,0};
            while (i < len) {
                uint32_t value = 0;
                value += (i < len) ? buf[i++] << 16 : 0;
                value += (i < len) ? buf[i++] <<  8 : 0;
                value += (i < len) ? buf[i++]       : 0;
                out[0] = BASE64_ALPHABET[(value >> 18) & 0x3F];
                out[1] = BASE64_ALPHABET[(value >> 12) & 0x3F];
                out[2] = BASE64_ALPHABET[(value >>  6) & 0x3F];
                out[3] = BASE64_ALPHABET[(value      ) & 0x3F];
                if (i < len) {
                    printf("%c%c%c%c", out[0], out[1], out[2], out[3]);
                }
            }
            if (len > 0) {
                switch (len % 3) {
                case 1:
                    out[2] = '=';
                case 2:
                    out[3] = '=';
                default:
                    break;
                }
                printf("%c%c%c%c\n", out[0], out[1], out[2], out[3]);
            }
        }
        log_trace("forge-socket", "Buf len: %d", len);
        fflush(stdout);
        free(buf);

    }

    if (st->state == COMPLETED) {
        bufferevent_free(bev);
        decrement_cur_running(st);
    }
}

int set_sock_state(int sock, struct tcp_state *st)
{
    struct sockaddr_in sin;
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = st->src_ip;
    sin.sin_port        = st->sport;

    int value = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        return -1;
    }

    if (setsockopt(sock, SOL_IP, IP_TRANSPARENT, &value, sizeof(value)) < 0) {
        perror("setsockopt IP_TRANSPARENT");
        return -1;
    }

    if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind");
        return -1;
    }

    if (setsockopt(sock, IPPROTO_TCP, TCP_STATE, st, sizeof(struct tcp_state)) < 0) {
        perror("setsockopt TCP_STATE");
        return -1;
    }

    return 0;
}

void grab_banner(struct state *st)
{
    struct sockaddr_in addr;
    struct bufferevent *bev;
    struct timeval read_to = {st->conf->read_timeout, 0};
    struct tcp_state tcp_st;
    int sock = socket(AF_INET, SOCK_FORGE, 0);

    addr.sin_addr.s_addr = st->src_ip;

    if (sock < 0) {
        perror("SOCK_FORGE socket");
        log_fatal("forge_socket", "(did you insmod forge_socket.ko?)");
        return;
    }

    memset(&tcp_st, 0, sizeof(tcp_st));

    // These need to be in network order for forge socket"
    tcp_st.src_ip = st->dst_ip;
    tcp_st.dst_ip = st->src_ip;
    tcp_st.sport = htons(st->dport);
    tcp_st.dport = htons(st->sport);

    // This should be in ???
    tcp_st.seq = st->seq_ack;
    tcp_st.ack = (st->seq + 1);

    tcp_st.snd_wnd = 0x1000;
    tcp_st.rcv_wnd = 0x1000;

    tcp_st.snd_una = tcp_st.seq;
    st->state = CONNECTING;
    st->conf->stats.init_connected_hosts++;

    // consider this a non-blocking, but completed "connect()". heh.
    if (set_sock_state(sock, &tcp_st) != 0) {
        log_error("forge_socket", "set_sock_state failed\n");
        decrement_cur_running(st);
        return;
    }

    evutil_make_socket_nonblocking(sock);

    bev = bufferevent_socket_new(st->conf->base, sock, BEV_OPT_CLOSE_ON_FREE);

    bufferevent_set_timeouts(bev, &read_to, &read_to);

    bufferevent_setcb(bev, read_cb, NULL, event_cb, st);
    bufferevent_enable(bev, EV_READ);

    // Update state/stats
    st->state = CONNECTED;

    st->conf->stats.connected_hosts++;

    log_trace("forge-socket", "go %s go! read a byte!!", inet_ntoa(addr.sin_addr));
}

void send_ssh_banner(struct state *st, struct bufferevent *bev) {
    struct sockaddr_in addr;
    addr.sin_addr.s_addr = st->src_ip;

    struct evbuffer *evout = bufferevent_get_output(bev);
    int x = evbuffer_add_printf(evout, "%s\n", SSH_CLIENT_BANNER);
    log_trace("forge-socket", "sent client banner (%d) to %s", x, inet_ntoa(addr.sin_addr));
}

size_t _ssh_ns(char * buf, char * msg, size_t offset, size_t len) {
    uint32_t x = htonl(len);
    memcpy(buf+offset, (char*)&x, sizeof(x));
    if (len > 0) {
        memcpy(buf+offset+sizeof(x), msg, len);
    }

    return sizeof(x)+len;
}

size_t _ssh_ns_str(char * buf, char * msg, size_t offset) {
    return _ssh_ns(buf, msg, offset, strlen(msg));
}

size_t _ssh_crc_packet(char * msgbuf, size_t len) {
    unsigned short bs = 8;
    unsigned long lenPad = bs - (len % bs);
    if (lenPad < 4) {
        lenPad = lenPad + bs;
    }

    uint32_t y = htonl(len-4 + lenPad);
    memcpy(msgbuf, (char*)&y, sizeof(y));
    msgbuf[4] = lenPad;
    memset(msgbuf+len, '\x0F', lenPad);
    return len + lenPad;
}

void send_kex_init(struct state *st, struct bufferevent *bev) {
    struct sockaddr_in addr;
    addr.sin_addr.s_addr = st->src_ip;

    struct evbuffer *evout = bufferevent_get_output(bev);

    size_t len = 5;
    char * msgbuf = malloc(1024);

    msgbuf[len] = MSG_KEXINIT;
    len++;
    memset((msgbuf+len), '\x0F', 16);
    len = len + 16;
    len = len + _ssh_ns_str(msgbuf, "diffie-hellman-group1-sha1", len);
    len = len + _ssh_ns_str(msgbuf, "ssh-dss,ssh-rsa", len);
    len = len + _ssh_ns_str(msgbuf, "aes256-ctr", len);
    len = len + _ssh_ns_str(msgbuf, "aes256-ctr", len);
    len = len + _ssh_ns_str(msgbuf, "hmac-sha1", len);
    len = len + _ssh_ns_str(msgbuf, "hmac-sha1", len);
    len = len + _ssh_ns_str(msgbuf, "none", len);
    len = len + _ssh_ns_str(msgbuf, "none", len);
    len = len + _ssh_ns_str(msgbuf, "", len);
    len = len + _ssh_ns_str(msgbuf, "", len);
    memset(msgbuf+len, '\x0', 5);
    len = len + 5;

    size_t packet_size = _ssh_crc_packet(msgbuf, len);
    evbuffer_add(evout, msgbuf, packet_size);
    free(msgbuf);
    log_trace("forge-socket", "sent MSG_KEXINIT (%d) to %s", packet_size, inet_ntoa(addr.sin_addr));
}

void send_kex_dh(struct state *st, struct bufferevent *bev) {
    struct sockaddr_in addr;
    addr.sin_addr.s_addr = st->src_ip;

    struct evbuffer *evout = bufferevent_get_output(bev);

    // static dh request - we do not need any dynamic DH request as it only contains random numbers
    char msgbuf[] = {
        0x00, 0x00, 0x00, 0x4c, 0x05,
        0x1e, 0x00, 0x00, 0x00, 0x41, 0x04, 0x55, 0xa5, 0xfb, 0xca, 0x82, 0x8c, 0xeb, 0xd0, 0x39, 0x80,
        0x21, 0x4d, 0x39, 0xb1, 0xe0, 0x5a, 0x9f, 0xc2, 0x44, 0xfb, 0x7a, 0x01, 0x4d, 0xee, 0x8e, 0x6f,
        0x5e, 0x87, 0xc5, 0x67, 0xec, 0x45, 0x2c, 0x0b, 0x36, 0xf8, 0xf7, 0x20, 0x3a, 0xb0, 0xec, 0x5b,
        0x11, 0x7e, 0x20, 0x61, 0x67, 0xe4, 0x6d, 0xe0, 0x37, 0xdc, 0x0e, 0x75, 0xaa, 0x3b, 0x85, 0xdb,
        0x29, 0xdf, 0x7d, 0x8b, 0xd0, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    evbuffer_add(evout, &msgbuf, 80);
    log_trace("forge-socket", "sent MSG_KEX_DH_INIT (80) to %s", inet_ntoa(addr.sin_addr));
}

void stdin_eventcb(struct bufferevent *bev, short events, void *ptr) {
    struct config *conf = ptr;

    if (events & BEV_EVENT_EOF) {
        log_debug("forge-socket",
                  "received EOF; quitting after buffer empties");
        conf->stdin_closed = 1;
        if (conf->current_running == 0) {
            log_info("forge-socket", "done");
            print_status(0, 0, conf);
            exit(0);
        }
    }
}

void stdin_readcb(struct bufferevent *bev, void *arg)
{
    struct evbuffer *in = bufferevent_get_input(bev);
    struct config *conf = arg;

    log_debug("forge-socket", "stdin cb %d < %d ?",
        conf->current_running, conf->max_concurrent);

    while (conf->current_running < conf->max_concurrent &&
           evbuffer_get_length(in) > 0) {
        size_t line_len;
        char *line = evbuffer_readln(in, &line_len, EVBUFFER_EOL_LF);
        struct state *st;
        if (!line)
            break;
        log_debug("forge-socket", "line: '%s'", line);

        //synack, 77.176.116.205, 141.212.121.125, 443, 49588, 3628826326, 3441755636, 0, 0,2013-08-11 19:16:05.799
        char synack[12];
        char srcip[INET_ADDRSTRLEN], dstip[INET_ADDRSTRLEN];
        uint32_t seq, seq_ack;
        uint16_t sport, dport;
        int cooldown, repeat=1;


        int ret = sscanf(line, "%11[^,], %15[^,], %15[^,], %hu, %hu, %u, %u, %d, %d,%*s",
            synack, srcip, dstip, &sport, &dport, &seq, &seq_ack, &cooldown, &repeat);

        log_trace("forge-socket", "%d '%s' sip: '%s', dip: '%s', sport: %d, dport: %d, seq: %d, seq_ack: %d",
            ret, synack, srcip, dstip, sport, dport, seq, seq_ack);

        if (ret==9 && !repeat && strcmp(synack, "synack") == 0) {
            st = malloc(sizeof(*st));
            st->conf = conf;
            st->src_ip = inet_addr(srcip);
            st->dst_ip = inet_addr(dstip);
            st->sport = sport;
            st->dport = dport;
            st->seq = seq;
            st->seq_ack = seq_ack;

            conf->current_running++;
            grab_banner(st);
        }
    }
}

int main(int argc, char *argv[])
{
    struct event_base *base;
    struct event *status_timer;
    struct timeval status_timeout = {1, 0};
    int c;
    struct option long_options[] = {
        {"concurrent", required_argument, 0, 'c'},
        {"read-timeout", required_argument, 0, 'r'},
        {"verbosity", required_argument, 0, 'v'},
        {"format", no_argument, 0, 'f'},
        {"data", required_argument, 0, 'd'},
        {0, 0, 0, 0} };

    struct config conf;
    int ret;
    FILE *fp;

    log_init(stderr, LOG_INFO, 1, "forge-socket");

    ret = ulimit(4, 1000000);    // Allow us to open 1 million fds (instead of 1024)
    if (ret < 0) {
        log_fatal("forge-socket", "cannot set ulimit");
        perror("ulimit");
        exit(1);
    }

    base = event_base_new();
    conf.base = base;

    // buffer stdin as an event
    conf.stdin_bev = bufferevent_socket_new(base, 0, BEV_OPT_DEFER_CALLBACKS);
    bufferevent_setcb(conf.stdin_bev, stdin_readcb, NULL, stdin_eventcb, &conf);
    bufferevent_enable(conf.stdin_bev, EV_READ);

    // Status timer
    status_timer = evtimer_new(base, print_status, &conf);
    evtimer_add(status_timer, &status_timeout);

    // Defaults
    conf.max_concurrent = 1;
    conf.current_running = 0;
    memset(&conf.stats, 0, sizeof(conf.stats));
    conf.read_timeout = 4;
    conf.stdin_closed = 0;
    conf.format = FORMAT_BASE64;

    // Parse command line args
    while (1) {
        int option_index = 0;
        c = getopt_long(argc, argv, "c:t:r:v:f:",
                long_options, &option_index);

        if (c < 0) {
            break;
        }

        switch (c) {
        case 'c':
            conf.max_concurrent = atoi(optarg);
            break;
        case 'r':
            conf.read_timeout = atoi(optarg);
            break;
        case 'v':
            if (atoi(optarg) >= 0 && atoi(optarg) <= 5) {
                log_init(stderr, atoi(optarg), 1, "forge-socket");
            }
            break;
        case 'f':
            if (strcmp(optarg, "hex") == 0) {
                conf.format = FORMAT_HEX;
            } else if (strcmp(optarg, "base64") == 0) {
                conf.format = FORMAT_BASE64;
            } else if (strcmp(optarg, "ascii") == 0) {
                conf.format = FORMAT_ASCII;
            } else {
                log_fatal("forge-socket", "Unknown format '%s'; use 'hex', 'base64', or 'ascii'",
                          optarg);
            }
            break;
        case '?':
            printf("Usage:\n");
            printf("\t%s [-c max_concurrency] [-r read_timeout] \n\t"
                   "[-v verbosity=0-5] [-f ascii|hex|base64]\n", argv[0]);
            exit(1);
        default:
            log_info("forge-socket", "hmmm..");
            break;
        }
    }

    log_info("forge-socket", "Using max_concurrency %d, %d s read timeout",
            conf.max_concurrent, conf.read_timeout);

    event_base_dispatch(base);

    return 0;
}

