#ifndef FLB_INPUT_PLUGIN_H
#define FLB_INPUT_PLUGIN_H

#define flb_plg_error(ins, fmt, ...) fprintf(stderr, "[plg_error] " fmt "\n", ##__VA_ARGS__)
#define flb_plg_warn(ins, fmt, ...)  fprintf(stderr, "[plg_warn]  " fmt "\n", ##__VA_ARGS__)
#define flb_plg_info(ins, fmt, ...)  fprintf(stderr, "[plg_info]  " fmt "\n", ##__VA_ARGS__)
#define flb_plg_debug(ins, fmt, ...) fprintf(stderr, "[plg_debug] " fmt "\n", ##__VA_ARGS__)

#endif
