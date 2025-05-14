#ifndef __COMMON_H
#define __COMMON_H

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256
#define FILEOPEN_EVENT_NB_RING 256

    typedef struct file_event {
        __u32 pid;
        char comm[TASK_COMM_LEN];
        char filename[FILENAME_LEN];
        __u32 flags;
        __u32 mode;
    } file_event;

#endif /* __COMMON_H */

