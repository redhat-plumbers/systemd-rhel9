/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

#include "conf-parser.h"
#include "in-addr-util.h"
#include "networkd-util.h"

typedef struct Link Link;
typedef struct Network Network;
typedef struct Request Request;

typedef struct AddressLabel {
        Network *network;
        NetworkConfigSection *section;

        unsigned char prefixlen;
        uint32_t label;
        struct in6_addr in_addr;
} AddressLabel;

AddressLabel *address_label_free(AddressLabel *label);

void network_drop_invalid_address_labels(Network *network);

int link_request_static_address_labels(Link *link);
int request_process_address_label(Request *req);

CONFIG_PARSER_PROTOTYPE(config_parse_address_label);
CONFIG_PARSER_PROTOTYPE(config_parse_address_label_prefix);
