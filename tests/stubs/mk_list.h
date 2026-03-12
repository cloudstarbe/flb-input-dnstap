#ifndef FLB_TEST_MK_LIST_H
#define FLB_TEST_MK_LIST_H

struct mk_list {
    struct mk_list *prev;
    struct mk_list *next;
};

#endif
