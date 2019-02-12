#include <stdlib.h>
#include <pcap.h>
#include "80211.h"
#include <argp.h>
#include "print_helpers.h"
#include "mac_address.h"

#define MAX_INTERFACE_LEN 16
#define MAX_SSID_LEN 16

static error_t parse_opt(int, char *, struct argp_state *);

struct pkt {
    size_t size;
    uint8_t * buf;
};

struct arguments {
    uint8_t mac_addr[6];
    char * interface;
    char * ssid;
    char * mac_addr_str;
};

struct pkt * create_probe_req(struct arguments g, int num_arg, ...);

int main(int argc, char **argv) {

    /* g will hold the globals */
    struct arguments g;
    g.interface = (char *) malloc(MAX_INTERFACE_LEN);
    g.ssid = (char *) malloc(MAX_SSID_LEN);
    g.mac_addr_str = (char *) malloc(18);

    struct argp argp = { 0, parse_opt, "<interface> <ssid>" };
    argp_parse(&argp, argc, argv, 0, 0, &g);

    get_mac_address(g.mac_addr, g.interface);
    mac_addr_to_str(g.mac_addr, g.mac_addr_str);
    fprintf(stderr, "%s MAC address assigned from interface default: %s\n", 
            status, g.mac_addr_str);
    
    /* create packet handle */
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0] = '\0';
    pcap_t *handle = pcap_open_live(g.interface, 96, 0, 0, pcap_errbuf);
    if (pcap_errbuf[0] != '\0') {
        print_error(pcap_errbuf);
        return -1;
    }

    /* create all necessary structures. Below is for immitating iOS device specifically */
    struct frame_variable *ssid = create_frame_variable(0, strlen(g.ssid),
                                                        g.ssid);
    const uint8_t rates_data[] = {0x02, 0x04, 0x0b, 0x16};
    struct frame_variable *rates = create_frame_variable(1, 4, &rates_data);
    const uint8_t extended_rates_data[] = {0x0c,0x12,0x18,0x24,
                                           0x30,0x48,0x60,0x6c};
    struct frame_variable *extended_rates = 
        create_frame_variable(50, 8,  &extended_rates_data);

    const uint8_t dsset_data[] = {0x01};
    struct frame_variable * dsset = create_frame_variable(3, 1, &dsset_data);

    const uint8_t htcaps_data[] = {0x2d,0x40,0x17,0xff,0x00,0x00,0x00,0x00,
                                 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                 0x00,0x00};
    struct frame_variable *htcaps = create_frame_variable(45, 26, &htcaps_data);
    const uint8_t ext_caps_data[] = {0x04,0x00,0x08,0x84};
    struct frame_variable *ext_caps = create_frame_variable(127, 4, &ext_caps_data);
    const uint8_t interworking_data[] = {0x0f,0xff,0xff,0xff,0xff,0xff,0xff};
    struct frame_variable *interworking =  create_frame_variable(107, 7, 
                                                                 interworking_data);
    const uint8_t apple_vendor_data[] = {0x00,0x17, 0xf2,0x0a,0x00,0x01,
                                         0x04,0x00,0x00,0x00,0x00};
    struct frame_variable *apple_vendor = create_frame_variable(221, 11,&apple_vendor_data);
    const uint8_t epigram_vendor_data[] = {0x00, 0x90, 0x4c,0x33,0x2d,0x40,0x17,
                                     0xff,0xff,0x00,0x00,0x00,0x00,0x00,
                                     0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                     0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                     0x00,0x00};
    struct frame_variable *epigram_vendor = create_frame_variable(221, 30, &epigram_vendor_data);
    const uint8_t microsoft_vendor_data[] = {0x00,0x50,0xf2,0x08};
    struct frame_variable *microsoft_vendor  = create_frame_variable(221,4, &microsoft_vendor_data);

    struct pkt * pkt = create_probe_req(g, 10, ssid, rates, extended_rates, dsset, htcaps, ext_caps, 
                                        interworking, apple_vendor, epigram_vendor, microsoft_vendor);

    if(pcap_sendpacket(handle, pkt->buf, pkt->size) != 0) {
        print_error(pcap_errbuf);
    }

    /* cleanup */
    pcap_close(handle);
    free(ssid);
    free(pkt->buf);
    free(g.mac_addr_str);
    free(g.interface);
    free(g.ssid);
}

struct pkt * create_probe_req(struct arguments g, int num_arg, ...) {
    struct pkt *ret = malloc(sizeof(struct pkt));

    /* parse variable args */
    va_list variable_params;
    va_start(variable_params, num_arg);
    size_t param_size = 0;
    struct frame_variable *params[num_arg];
    for (int i = 0; i < num_arg; i++) {
        struct frame_variable *cur = va_arg(variable_params,
                                            struct frame_variable *);
        param_size += cur->len + sizeof(struct frame_variable);
        params[i] = cur;
    }
    size_t size;
    
    size = sizeof(radioTapHeader)
         + sizeof(struct i80211_hdr)
         + param_size;

    ret->buf = malloc(size);
    uint8_t *cur = ret->buf;

    memcpy(cur, radioTapHeader, RADIOTAP_LEN);
    cur += RADIOTAP_LEN;

    struct i80211_hdr *hdr = (struct i80211_hdr *) cur;
    hdr->frame_ctrl = WLAN_FC_SUBTYPE_PROBE_REQ;
    hdr->duration_id = 0x0000;
    memcpy(hdr->addr1, BROADCAST_MAC, MAC_LEN);
    memcpy(hdr->addr3, BROADCAST_MAC, MAC_LEN);
    memcpy(hdr->addr2, g.mac_addr, MAC_LEN);
    cur += sizeof(struct i80211_hdr);

    for (int i = 0; i < num_arg; i++) {
        memcpy(cur, params[i], params[i]->len + sizeof(struct frame_variable));
        cur += params[i]->len + sizeof(struct frame_variable);
    }
    va_end(variable_params);
    ret->size = size;
    return ret;
}


static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;
    switch(key) {
        case ARGP_KEY_ARG:
            {
                if ( 2 <= state->arg_num) {
                    argp_error(state, "Too many arguments");
                } else {
                    /* following is probably not right way */
                    if(state->arg_num == 0) {
                        strncpy(arguments->interface, arg, MAX_INTERFACE_LEN);
                        fprintf(stderr,"%s Interface set to %s\n", status, 
                                arguments->interface);
                    }
                    else {
                        strncpy(arguments->ssid, arg, MAX_SSID_LEN);
                        fprintf(stderr, "%s SSID set to %s\n", status,
                                arguments->ssid);
                    }
                }
            }
            break;
        case ARGP_KEY_END:
            {
                if (2 > state->arg_num) {
                    argp_usage(state);
                }
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

