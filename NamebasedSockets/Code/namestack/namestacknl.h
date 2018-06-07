#ifndef NAMESTACKNL_H
#define NAMESTACKNL_H

/* Message types */
enum {
    NAME_STACK_REGISTER,
    /* FIXME: a QUERY is sent by the kernel to the daemon, and never
     * vice-versa.  Should I separate message types by the direction they're
     * sent?
     */
    NAME_STACK_NAME_QUERY,
    NAME_STACK_NAME_REPLY,
    NAME_STACK_QUALIFY_QUERY,
    NAME_STACK_QUALIFY_REPLY,
    NAME_STACK_REGISTER_QUERY,
    NAME_STACK_REGISTER_REPLY,
    NAME_STACK_REGISTER_DELETE
};

#endif
