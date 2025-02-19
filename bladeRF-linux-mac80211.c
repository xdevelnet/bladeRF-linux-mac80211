/*
 * This file is part of the bladeRF-linux-mac80211 project
 *
 * Copyright (C) 2020 Nuand LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/genetlink.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libbladeRF.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include "bladeRF-wiphy.h"

pthread_mutex_t log_mutex;

struct bladerf *bladeRF_dev;
unsigned int local_freq = 0;
unsigned int local_tx_freq = 0;
unsigned int force_freq = 0;
unsigned int updated_freq = 0;
unsigned int half_rate_only = 0;
int tx_gain = 0;
int tx_mod = 0;
int disable_agc = 0;
int rx_gain = 0;
int tun_tap = 0;
int tun_tap_fd = 0;

bool debug_mode = 1;

struct nl_sock *netlink_sock = NULL;
int netlink_family = 0;

struct tx_rate {
   uint8_t idx;
   uint8_t count;
};

struct tx_rate_info {
   uint8_t  idx;
   uint16_t info;
};

int set_new_frequency(unsigned long freq);
int rx_frame(struct nl_sock *netlink_sock, int netlink_family, uint8_t *ptr, int len, int mod);
int start_mac80211(char *cmd);
int start_tun_tap(char *cmd);


unsigned int bytes_to_dwords(int bytes) {
    return (bytes + 3) / 4;
}

int bladerf_tx_frame(uint8_t *data, int len, int modulation, uint64_t cookie) {
    int frame_len = len + (int) sizeof(struct bladeRF_wiphy_header_tx);
    void *frame = calloc(1, frame_len);
    struct bladeRF_wiphy_header_tx *bwh_t = frame;
    memcpy(frame + sizeof(struct bladeRF_wiphy_header_tx), data, len);

    //char msg[] = "\x55\x66\x00\x00" "\x07\x00\x02\x00" "\x0a\x00\x9a\x00" "\x00\x00\x00\x00" ;
    //memcpy(frame, msg, sizeof(msg)-1);
    //printf("PING\n");

    bwh_t->len = len;

    if (half_rate_only) {
       if (modulation == 1 || modulation == 3) {
          modulation--;
       } else if (modulation > 4) {
          modulation = 4;
       }
    }

    bwh_t->modulation = modulation;
    bwh_t->bandwidth = 2;
    bwh_t->cookie = cookie;

    if (debug_mode > 2) {
        printf("TX =...");
        fflush(stdout);
    }
    //int f;
    //for (f = 0; f < frame_len; f++) {
    //   printf("\\x%.2x", frame[f]);
    //}

    struct bladerf_metadata meta = {.flags = 0};
    int status = bladerf_sync_tx(bladeRF_dev, frame, bytes_to_dwords(frame_len), &meta, 0);
    if (debug_mode > 2) {
        printf("%d\n", status);
    }

    free(frame);

    return 0;
}

void dump_packet(uint8_t *payload_data, int payload_len) {
    int i;
    printf("Frame payload (len=%d):\n", payload_len);
    for (i = 0; i < payload_len; i++) {
        if ((i % 16) == 0) {
            printf("  %.4x :", i);
        }
        printf(" %.2x", payload_data[i]);

        if ((i % 16) == 15) {
            printf("\n");
        }
    }
}


int netlink_frame_callback(struct nl_msg *netlink_message, void *arg) {
    struct nlattr *attribute_table[25 /* MAX */ + 1];
    struct nlmsghdr *netlink_header = nlmsg_hdr(netlink_message);
    struct genlmsghdr *genlink_header = genlmsg_hdr(netlink_header);

    if (genlink_header->cmd != 2 /* FRAME */ && genlink_header->cmd != 7 /* FREQ */) {
        return 0;
    }

    /* parse attributes into table */
    int genlink_attribute_len = genlmsg_attrlen(genlink_header, 0);
    struct nlattr *genlink_attribute_head = genlmsg_attrdata(genlink_header, 0);
    nla_parse(attribute_table, 25 /* MAX */, genlink_attribute_head,  genlink_attribute_len, NULL);

    uint32_t frequency = nla_get_u32(attribute_table[19 /* FREQ */]);

    if (genlink_header->cmd == 7 /* FRAME */) {
        set_new_frequency(frequency);
        updated_freq = 1;

        return 0;
    }

    uint8_t *payload_data = nla_data(attribute_table[3 /* FRAME */]);
    int payload_len = nla_len(attribute_table[3 /* FRAME */]);
    struct tx_rate *tx_rate = nla_data(attribute_table[7 /* TX RATE */]);
    uint64_t cookie = nla_get_u64(attribute_table[8 /* COOKIE */]);

    if (debug_mode) {
        uint8_t *mac = nla_data(attribute_table[2 /* TRANSMITTER */]);
        uint32_t flags = nla_get_u32(attribute_table[4 /* FLAGS */]);
        int tx_rate_len = nla_len(attribute_table[7 /* TX RATE */]);
        struct tx_rate_info *tx_rate_info = nla_data(attribute_table[21 /* TX RATE INFO */]);
        int tx_rate_info_len = nla_len(attribute_table[21 /* TX RATE INFO */]);
        uint8_t frame_type = (payload_data[0] >> 2) & 0x3;
        //pthread_mutex_lock(&log_mutex);
        printf("TX frame:\n");
        printf("Frame cookie = %lu\n", cookie);
        /* display center frequency of channel in MHz */
        printf("Frequency = %d\n", frequency);

        /* display MAC address of transmitter */
        printf("TX MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac[0], mac[1], mac[2],
               mac[3], mac[4], mac[5]);

        /* display TX rate selection table */
        printf("Rates:\n");
        for (int i = 0; i < (tx_rate_len / sizeof(struct tx_rate)); i++) {
            if (tx_rate[i].idx == 255)
                break;
            printf("   [%d] rate=%d count=%d\n", i, tx_rate[i].idx, tx_rate[i].count);
        }
        printf("Rate info:\n");
        for (int i = 0; i < (tx_rate_info_len / sizeof(struct tx_rate_info)); i++) {
            if (tx_rate_info[i].idx == 0)
                break;
            printf("   [%d] rate=%d rate_info=%d\n", i, tx_rate_info[i].idx, tx_rate_info[i].info);
        }

        printf("Flags: %x (tx_status_req=%d, no_ack=%d, stat_ack=%d)\n",
               flags, !!(flags & 1), !!(flags & 2), !!(flags & 4));
        printf("Payload type: ");
        if (frame_type == 0) {
            printf("Management");
        }
        printf("\n");

        dump_packet(payload_data, payload_len);
        printf("\n\n\n");
        //pthread_mutex_unlock(&log_mutex);
    }

    return bladerf_tx_frame(payload_data, payload_len, tx_rate[0].idx, cookie);
}

int tx_cb(struct nl_sock *netlink_sock, int netlink_family, struct bladeRF_wiphy_header_rx *bwh_r) {
    if (bwh_r == NULL) return -1;
    struct nl_msg *netlink_msg = nlmsg_alloc();
    if (netlink_msg == NULL) {
        printf("Failed to allocate netlink message\n");
        return -1;
    }

    genlmsg_put(netlink_msg, NL_AUTO_PORT, NL_AUTO_SEQ, netlink_family, 0, 0, /* TX INFO */ 3, 0);
    nla_put(netlink_msg, 2 /* TRANSMITTER */, 6, "\x42\x00\x00\x00\x00\x00");
    nla_put_u32(netlink_msg, 4 /* FLAGS */, /* ACK */ bwh_r->type == 2 ? 4 : 0);
    struct tx_rate tr[4] = {0};
    tr[0].idx = bwh_r->modulation;
    tr[0].count = 1;
    nla_put_u32(netlink_msg, 6 /* SIGNAL */, -30);
    nla_put(netlink_msg, 7 /* RATE */, sizeof(tr), &tr);
    nla_put_u64(netlink_msg, 8 /* COOKIE */, bwh_r->cookie);

    int status = nl_send_auto(netlink_sock, netlink_msg);
    nlmsg_free(netlink_msg);
    if (status < 0) {
        printf("nl_send_auto() failed with error=%d\n", status);
        return -1;
    }

    return 0;
}

int rx_frame(struct nl_sock *netlink_sock, int netlink_family, uint8_t *ptr, int len, int mod) {
    if (ptr == NULL) return -1;
    struct nl_msg *netlink_msg = nlmsg_alloc();
    if (netlink_msg == NULL) {
        printf("Failed to allocate netlink message\n");
        return -1;
    }

    void *ret_ptr = genlmsg_put(netlink_msg, NL_AUTO_PORT, NL_AUTO_SEQ, netlink_family, 0, 0, /* FRAME */ 2, 0);
    if (!ret_ptr) {
        printf("genlmsg_put() failed\n");
        return -1;
    }
    nla_put(netlink_msg, 1 /* RECEIVER */, 6, "\x42\x00\x00\x00\x00\x00");
    nla_put(netlink_msg, 3 /* FRAME */, len, ptr);
    int band_rate_modifier = (local_freq > 2500) ? 0 : 4;
    nla_put_u32(netlink_msg, 5 /* RX RATE */, mod + band_rate_modifier);
    nla_put_u32(netlink_msg, 6 /* SIGNAL */, -50);
    if (!force_freq && updated_freq)
        nla_put_u32(netlink_msg, 19 /* FREQ */, local_freq);

    int status = nl_send_auto(netlink_sock, netlink_msg);
    nlmsg_free(netlink_msg);
    if (status < 0) {
        printf("nl_send_auto() failed with error=%d\n", status);
        return -1;
    }

    return 0;
}

int set_new_frequency(unsigned long freq) {
    unsigned long tx_freq;
    int status = 0;

    if (force_freq)
        return 0;

    if (freq == local_freq)
        return 0;

    if (!bladeRF_dev)
        return 0;

    if (debug_mode) {
        printf("Changing channel to %luMHz\n", freq);
    }

    status = bladerf_set_frequency(bladeRF_dev, BLADERF_CHANNEL_RX(0), freq * 1000UL * 1000UL);
    if (status != 0) {
        printf("Could not set RX frequency to freq=%luMHz, error=%d", freq, status);
        return status;
    }

    if (local_tx_freq) {
        tx_freq = local_tx_freq;
    } else {
        tx_freq = freq;
    }
    status = bladerf_set_frequency(bladeRF_dev, BLADERF_CHANNEL_TX(0), tx_freq * 1000UL * 1000UL);
    if (status != 0) {
        printf("Could not set TX frequency to freq=%luMHz, error=%d", tx_freq, status);
        return status;
    }

    printf("Set RX to %luMHz and TX to %luMHz\n", freq, tx_freq);

    local_freq = freq;

    return 0;
}

int config_bladeRF(char *dev_str) {
    const int num_buffers = 4096;
    const int num_dwords_buffer = 4096; // 4096 bytes
    const int num_transfers = 16;
    const int stream_timeout = 10000000;

#define TWENTY_MHZ (20 * 1000 * 1000)
    bladerf_sample_rate sample_rate = TWENTY_MHZ;
    bladerf_bandwidth req_bw = TWENTY_MHZ;
    bladerf_bandwidth actual_bw;

    printf("Opening bladeRF with dev_str=%s\n", dev_str ? dev_str : "(NULL)");
    int status = bladerf_open(&bladeRF_dev, NULL);
    if (status != 0) {
        printf("Error opening bladeRF error=%d\n", status);
        return status;
    }

    struct bladerf_version fpga_ver;
    status = bladerf_fpga_version(bladeRF_dev, &fpga_ver);
    if (status != 0) {
        printf("Could not query FPGA version, error=%d\n", status);
        return status;
    }

    if (fpga_ver.major == 0 && fpga_ver.minor < 12) {
        printf("FPGA version %d.%d.%d detected, "
               "however at minimum FPGA version 0.12.0 is required.\n",
               fpga_ver.major, fpga_ver.minor, fpga_ver.patch);
        return -1;
    }

    status = bladerf_sync_config(bladeRF_dev, BLADERF_RX_X1,
                                 BLADERF_FORMAT_PACKET_META, num_buffers, num_dwords_buffer,
                                 num_transfers, stream_timeout);
    if (status != 0) {
        printf("Could not config RX sync config, error=%d\n", status);
        return status;
    }

    status = bladerf_sync_config(bladeRF_dev, BLADERF_TX_X1,
                                 BLADERF_FORMAT_PACKET_META, num_buffers, num_dwords_buffer,
                                 num_transfers, stream_timeout);
    if (status != 0) {
        printf("Could not config TX sync config, error=%d\n", status);
        return status;
    }

    status = bladerf_set_sample_rate(bladeRF_dev, BLADERF_CHANNEL_RX(0),
                                     sample_rate, NULL);
    if (status != 0) {
        printf("Could not set RX sample rate, error=%d\n", status);
        return status;
    }

    status = bladerf_set_sample_rate(bladeRF_dev, BLADERF_CHANNEL_TX(0),
                                     sample_rate, NULL);
    if (status != 0) {
        printf("Could not set TX sample rate, error=%d\n", status);
        return status;
    }

    if (disable_agc) {
        if (debug_mode) {
            printf("Disabling AGC and setting RX gain to %d\n", rx_gain);
        }
        status = bladerf_set_gain_mode(bladeRF_dev, BLADERF_CHANNEL_RX(0), BLADERF_GAIN_MGC);
        if (status != 0) {
            printf("Could not disable AGC and set RX gain mode to manual, error=%d\n", status);
            return status;
        }
        status = bladerf_set_gain(bladeRF_dev, BLADERF_CHANNEL_RX(0), rx_gain);
        if (status != 0) {
            printf("Could not set manual RX gain, error=%d\n", status);
            return status;
        }
    }

    status = bladerf_enable_module(bladeRF_dev, BLADERF_MODULE_TX, true);
    if (status != 0) {
        printf("Could not enable TX module, error=%d\n", status);
        return status;
    }

    status = bladerf_enable_module(bladeRF_dev, BLADERF_MODULE_RX, true);
    if (status != 0) {
        printf("Could not enable RX module, error=%d\n", status);
        return status;
    }
    bladerf_set_gain_stage(bladeRF_dev, BLADERF_CHANNEL_TX(0), "dsa", tx_gain);
    bladerf_set_bias_tee(bladeRF_dev, BLADERF_CHANNEL_RX(0), true);
    bladerf_set_bias_tee(bladeRF_dev, BLADERF_CHANNEL_RX(1), true);
    bladerf_set_bias_tee(bladeRF_dev, BLADERF_CHANNEL_TX(0), true);
    bladerf_set_bias_tee(bladeRF_dev, BLADERF_CHANNEL_TX(1), true);
    // do we really need all amps enabled? separate enable/disable each of them do not work

    status = bladerf_set_bandwidth(bladeRF_dev, BLADERF_CHANNEL_RX(0), req_bw, &actual_bw);
    if (status != 0) {
        printf("Could not set RX bandwidth, error=%d\n", status);
        return status;
    }
    printf("RX bandwidth set to %d Hz\n", actual_bw);

    status = bladerf_set_bandwidth(bladeRF_dev, BLADERF_CHANNEL_TX(0), req_bw, &actual_bw);
    if (status != 0) {
        printf("Could not set TX bandwidth, error=%d\n", status);
        return status;
    }
    printf("TX bandwidth set to %d Hz\n", actual_bw);


    return 0;
}

int receive_test() {
    void *data = calloc(16, 4096);
    uint8_t *lut = NULL;
    uint32_t max_cnt = 0;
    while (1) {
        struct bladerf_metadata meta = {0};
        struct bladeRF_wiphy_header_rx *bwh_r = data;
        if (!max_cnt) fprintf(stderr, "Awaiting first benchmark packet.");
        int status = bladerf_sync_rx(bladeRF_dev, data, 1000, &meta, max_cnt ? 2500 : 0);
        if (status == BLADERF_ERR_TIMEOUT) {
            int i;
            int cnt = 0;
            for (i = 0; i < max_cnt; i++) {
                if (lut[i])
                    cnt++;
            }
            printf("Packet success rate: %f %%\n", 100 * ((float) cnt) / max_cnt);
            free(data);
            free(lut);
            return 0;
        }

        if (status) break;
        if (bwh_r->len - 4 < 32) continue;
        if (memcmp(data + 16, "\x12\x34\x56\x78", 4) != 0) continue;
        if (!lut) {
            max_cnt = *(uint32_t *) (data + 16 + 28);
            lut = (uint8_t *) malloc(sizeof(uint8_t) * max_cnt);
            if (!lut) break;
            memset(lut, 0, sizeof(uint8_t) * max_cnt);
        }
        uint32_t tmp = *(uint32_t *) (data + 16 + 32);
        if (tmp > max_cnt) continue;
        lut[tmp] = 1;
        fprintf(stderr, "\r%d / %d                       \r", tmp, max_cnt);
    }

    free(lut);
    free(data);

    return -1;
}

void *rx_thread(void *arg) {
    bladerf_trim_dac_write(bladeRF_dev, 0x0ea8);
    uint8_t data[4096 * 16] = {0};
    while (1) {
        struct bladerf_metadata meta = {0};
        bladerf_sync_rx(bladeRF_dev, data, 1000, &meta, 0);
        struct bladeRF_wiphy_header_rx *bwh_r = (struct bladeRF_wiphy_header_rx *) data;
        if (debug_mode) {
            //pthread_mutex_lock(&log_mutex);
            printf("RX frame:\n");
            if (debug_mode > 2) {
                printf("Bytes:\n");
                for (int i = 0; i < 48; i++)
                    printf("%.2x ", data[i]);
            }

            char *type_str = "Unknown";
            if (bwh_r->type == 1) {
                type_str = "Packet";
            } else if (bwh_r->type == 2) {
                type_str = "ACK";
            } else if (bwh_r->type == 3) {
                type_str = "Missing ACK";
            }

            printf("Type:   %d (%s)\n", bwh_r->type, type_str);
            if (bwh_r->type == 1) {
                printf("Length: %d\n", bwh_r->len);
                printf("Rsvd2:  0x%.8x\n", bwh_r->rsvd2);
            } else {
                printf("Cookie: %d\n", bwh_r->cookie);
            }
            printf("Modulation: %d\n", bwh_r->modulation);
            printf("Bandwidth:  %d\n", bwh_r->bandwidth);
            printf("Rsvd3:      0x%.8x\n", bwh_r->rsvd3);

            if (bwh_r->type == 1)
                dump_packet(data + 16, bwh_r->len);
            printf("\n\n\n");
            //pthread_mutex_unlock(&log_mutex);
        }

        if (tun_tap) {
            if (bwh_r->type == 1) {
                write(tun_tap_fd, data + 16, bwh_r->len - 4);
            }
            continue;
        }

        if (bwh_r->type == 1) {
            rx_frame(netlink_sock, netlink_family, data + 16, bwh_r->len - 4, bwh_r->modulation);
            continue;
        }

        tx_cb(netlink_sock, netlink_family, bwh_r);
    }
}

int transmit_test(uint32_t count, int mod, int length) {
    void *data = calloc(1, length + 40);
    memcpy(data, "\x12\x34\x56\x78", 4);
    memset(data + 4, 0xff, 18);
    memcpy(data + 28, &count, sizeof(count));

    printf("Sending %d packets at %d modulation and %d bytes long:\n", count, mod, length);
    for (int i = 0; i < count; i++) {
        memcpy(data + 32, &i, sizeof(i));
        bladerf_tx_frame(data, length, mod, 0xbd81);
    }
    sleep(5);
    free(data);
    return 0;
}

#ifndef LIBBLADERF_API_VERSION
#error LIBBLADERF_API_VERSION is not defined in headers. At minimum libbladeRF version 2.4.0 is required.
#endif
#if ( LIBBLADERF_API_VERSION < 0x2040000 )
#error Incompatible libbladeRF header version. At minimum libbladeRF version 2.4.0 is required.
#endif

int main(int argc, char *argv[]) {
    unsigned long freq = 0;
    int trx_test = 0;
#define TRX_TEST_NONE 0
#define TRX_TEST_RX   1
#define TRX_TEST_TX   2
    int tx_count = 100;
    int tx_len = 200;
    int cmd;

    pthread_mutex_init(&log_mutex, NULL);
    struct bladerf_version ver;

    bladerf_version(&ver);
    if (ver.major < 2 || (ver.major == 2 && ver.minor < 4)) {
        printf("Incorrect version (%d.%d.%d) of libbladeRF detected.\n"
               "At minimum libbladeRF version 2.4.0 is required.\n",
               ver.major, ver.minor, ver.patch);
        return -1;
    }

    char *dev_str = NULL;
    while (-1 != (cmd = getopt(argc, argv, "rt:l:c:d:f:s:a:g:m:vVhHT"))) {
        if (cmd == 'd') {
            dev_str = strdup(optarg);
        } else if (cmd == 'f') {
            freq = atol(optarg);
            printf("Overriding RX/TX frequency to %luMHz\n", freq);
        } else if (cmd == 's') {
            local_tx_freq = atol(optarg);
            printf("Overriding TX frequency to %luMHz\n", freq);
        } else if (cmd == 'r') {
            trx_test = TRX_TEST_RX;
        } else if (cmd == 'c') {
            tx_count = atol(optarg);
        } else if (cmd == 'l') {
            tx_len = atol(optarg);
        } else if (cmd == 'm') {
            tx_mod = atol(optarg);
        } else if (cmd == 't') {
            trx_test = TRX_TEST_TX;
            tx_mod = atol(optarg);
        } else if (cmd == 'a') {
            disable_agc = 1;
            rx_gain = atoi(optarg);
            printf("Overriding AGC and setting RX gain to %d\n", rx_gain);
        } else if (cmd == 'g') {
            tx_gain = atol(optarg);
            printf("Overriding DSA gain to %d\n", tx_gain);
        } else if (cmd == 'v') {
            debug_mode = 10;
        } else if (cmd == 'V') {
            debug_mode = 0;
        } else if (cmd == 'H') {
            half_rate_only = 1;
            printf("Overriding rate selection to half rates\n");
        } else if (cmd == 'T') {
            tun_tap = 1;
        } else if (cmd == 'h') {
            fprintf(stderr,
                    "usage: bladeRF-linux-mac80211 [-d device_string] [-f frequency] [-s TX_frequency] [-H] [-r] [-t <tx test modulation>]\n"
                    "                              [-m TX_mod] [-c count] [-l length] [-v] [-V] [-a RX_gain] [-g tx_dsa_gain] [-T]\n"
                    "\n"
                    "\t\n"
                    "\tdevice_string, uses the standard libbladeRF bladerf_open() syntax\n"
                    "\tfrequency, center frequency expressed in MHz\n"
                    "\ttx_dsa_gain, maximum gain occurs at `0', values are in dB\n"
                    "\tRX_gain, setting this disables AGC, and sets the RX gain to the specified number\n"
                    "\tTX_frequency, specifies the split TX frequency\n"
                    "\tTX_mod, override TX modulation\n"
                    "\t-H selects half rates\n"
                    "\t-v enables very verbose mode\n"
                    "\t-V disables verbose mode entirely\n"
                    "\t-T enable TUN/TAP\n"
            );
            return -1;
        }
    }

    if (config_bladeRF(dev_str)) {
        return -1;
    }

    if (trx_test != TRX_TEST_NONE) {
        set_new_frequency(freq);
        force_freq = 1;
        if (trx_test == TRX_TEST_RX) {
            return receive_test();
        }

        if (tx_len < 32) {
            printf("specify a packet length greater than 32 with -l\n");
            return -1;
        }

        return transmit_test(tx_count, tx_mod, tx_len);
    }

    int status;
    if (freq) {
        status = set_new_frequency(freq);
        force_freq = 1;
    } else {
        status = set_new_frequency(2412);
    }

    if (status) {
        printf("Could not set frequency\n");
        return -1;
    }

    if (tun_tap) return start_tun_tap(argv[0]);
    return start_mac80211(argv[0]);

}

int start_mac80211(char *cmd) {
    netlink_sock = nl_socket_alloc();
    if (netlink_sock == NULL) {
        printf("nl_socket_alloc() failed\n");
        return -1;
    }

    /* connect netlink socket to generic netlink family MAC80211_HWSIM */
    int status = genl_connect(netlink_sock);
    if (status) {
        printf("genl_connect() failed with error=%d\n", status);
        return -1;
    }

    netlink_family = genl_ctrl_resolve(netlink_sock, "MAC80211_HWSIM");
    if (netlink_family < 0) {
        printf("genl_ctrl_resolve() failed with error=%d\n", netlink_family);
        printf("perhaps mac80211_hwsim.ko isn't loaded?\n");
        return -1;
    }

    /* create and set netlink_frame_callback as netlink callback */
    struct nl_cb *netlink_cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!netlink_cb) {
        printf("nl_cb_alloc() failed\n");
        return -1;
    }

    status = nl_cb_set(netlink_cb, NL_CB_MSG_IN, NL_CB_CUSTOM, netlink_frame_callback, NULL);
    if (status) {
        printf("nl_cb_set() failed with error=%d\n", status);
        return -1;
    }


    /* send HWSIM_CMD_REGISTER generic netlink message */
    struct nl_msg *netlink_msg = NULL;
    netlink_msg = nlmsg_alloc();
    void *ret_ptr = genlmsg_put(netlink_msg, NL_AUTO_PORT, NL_AUTO_SEQ, netlink_family, 0, 0, /* REGISTER */ 1, 0);
    if (ret_ptr == NULL) {
        printf("genlmsg_put() failed\n");
        return -1;
    }

    status = nl_send_auto(netlink_sock, netlink_msg);
    nlmsg_free(netlink_msg);
    if (status < 0) {
        printf("nl_send_auto() failed with error=%d\n", status);
        return -1;
    }

    printf("netlink registration complete\n");

    pthread_t rx_th;
    pthread_create(&rx_th, NULL, rx_thread, NULL);

    /* receive and dispatch netlink messages */
    while (1) {
        status = nl_recvmsgs(netlink_sock, netlink_cb);
        if (status == -NLE_PERM) {
            printf("attain CAP_NET_ADMIN via `sudo setcap cap_net_admin+eip %s` "
                   "or start again with sudo\n", cmd);
            return -1;
        }
        if (status != NLE_SUCCESS && status != -NLE_SEQ_MISMATCH && status != -7 && status != -8) {
            printf("nl_recvmsgs() failed with error=%d\n", status);
            return -1;
        }
    }

    return 0;
}

int start_tun_tap(char *cmd) {
    tun_tap_fd = open("/dev/net/tun", O_RDWR);
    if (tun_tap == -EPERM) {
        printf("attain CAP_NET_ADMIN via `sudo setcap cap_net_admin+eip %s` "
               "or start again with sudo\n", cmd);
        return -1;
    }

    if (tun_tap == -ENOENT) {
        printf("start_tun_tap() failed with error=%d\n", netlink_family);
        printf("perhaps tun.ko isn't loaded?\n");
    }

    struct ifreq ifreq = {.ifr_flags = IFF_TAP | IFF_NO_PI};
    strncpy(ifreq.ifr_name, "bladelan", IFNAMSIZ);
    int status = ioctl(tun_tap_fd, TUNSETIFF, &ifreq);
    if (status) {
        printf("could not ioctl(TUNSETIFF), error=%d\n", status);
        close(tun_tap_fd);
        return -1;
    }

    printf("Registered `%s' TAP interface\n", ifreq.ifr_name);

    pthread_t rx_th;
    pthread_create(&rx_th, NULL, rx_thread, NULL);

    while (1) {
        uint8_t payload_data[4096];
        ssize_t got = read(tun_tap_fd, payload_data, sizeof(payload_data));
        if (got < 0) {
            return -1;
        }

        if (debug_mode) {
            printf("TAP TX frame:\n");
            printf("\tMod: %d\n", tx_mod);
            dump_packet(payload_data, (int) got);
            printf("\n\n");
        }

        bladerf_tx_frame(payload_data, (int) got, tx_mod, 0);
    }

    return 0;
}
