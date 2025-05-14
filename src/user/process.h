#ifndef __PROCESS_H
#define __PROCESS_H

    #define MAX_PID_LEN 11
    #define CMDLINE_SUFFIX "/cmdline"
    #define PROCESS_PATH_CMDLINE_LEN (sizeof("/proc/") + MAX_PID_LEN + sizeof(CMDLINE_SUFFIX))
    #define STATUS_SUFFIX "/status"
    #define PROCESS_PATH_STATUS_LEN (sizeof("/proc/") + MAX_PID_LEN + sizeof(STATUS_SUFFIX))

    #define MAX_CMDLINE_LEN 512
    #define MAX_STATUS_LEN 512

    #define UID_ERR 4294967295U


    #include <stdint.h>
    #include <sys/types.h>


    struct process_user_info
    {
        uid_t uid;
        char name[MAX_STATUS_LEN];
    };


    void get_process_cmdline(uint32_t pid, char *dest, size_t max_len);
    void get_username_from_pid(uint32_t pid,struct process_user_info * info, size_t max_name_len);

#endif /* __PROCESS_H */
