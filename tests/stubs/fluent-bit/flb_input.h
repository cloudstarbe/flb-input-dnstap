#ifndef FLB_INPUT_H
#define FLB_INPUT_H

#include "../mk_list.h"

struct flb_input_instance;
struct flb_config;
struct flb_connection {
    int fd;
    void *user_data;
};

#endif
