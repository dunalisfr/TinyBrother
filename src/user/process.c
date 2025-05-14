#include "process.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <pwd.h>

void get_process_cmdline(uint32_t pid, char *dest, size_t max_len) {
    char path[PROCESS_PATH_CMDLINE_LEN];
    snprintf(path, sizeof(path), "/proc/%u/cmdline", pid);

    FILE *file = fopen(path, "rb");
    if (!file) {
        perror("fopen");
        strncpy(dest, "unknown", max_len-1);
        dest[sizeof("unknown") < max_len ? sizeof("unknown"): max_len-1  ] = '\0';
        return;
    }

    size_t bytes_read = fread(dest, 1, max_len - 1, file);
    fclose(file);

    if (bytes_read == 0) {
        strncpy(dest, "unknown", max_len-1);
        dest[sizeof("unknown") < max_len ? sizeof("unknown"): max_len-1  ] = '\0';
        return;
    }

    for (size_t i = 0; i < bytes_read - 1; ++i) {
        if (dest[i] == '\0') dest[i] = ' ';
    }

    dest[bytes_read] = '\0';
}

static inline void make_unknown_user_info(struct process_user_info * info, size_t max_name_len) {
    info->uid = UID_ERR;
    strncpy(info->name, "unknown", max_name_len-1);
    info->name[sizeof("unknown") < max_name_len ? sizeof("unknown"): max_name_len-1  ] = '\0';
}


void get_username_from_pid(uint32_t pid,struct process_user_info * info, size_t max_name_len) {
    char path[PROCESS_PATH_STATUS_LEN];
    
    snprintf(path, sizeof(path), "/proc/%u/status", pid);

    FILE *file = fopen(path, "r");
    if (!file) {
        perror("fopen");
        make_unknown_user_info(info,max_name_len);
        return;
    }

    char line[MAX_STATUS_LEN];
    uid_t uid = (uid_t)-1;

    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            sscanf(line, "Uid:\t%u", &uid);
            break;
        }
    }

    fclose(file);

    if (uid == (uid_t)-1) {
        fprintf(stderr, "UID not found in %s\n", path);
        make_unknown_user_info(info,max_name_len);
        return;
    }

    struct passwd *pw = getpwuid(uid);
    if (!pw) {
        fprintf(stderr, "No user for UID %u\n", uid);
        make_unknown_user_info(info,max_name_len);
        return;
    }

    info->uid = uid;
    strncpy(info->name,pw->pw_name,max_name_len-1);
    info->name[max_name_len-1] = '\0';
}
