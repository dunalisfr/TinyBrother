#include "file_open.h"

#include <stdio.h>
#include <string.h>

int load_watched_files(const char *config_path, char watched_files[][256],size_t max_files, size_t max_path_len, size_t *loaded_count_out) {
    FILE *file = fopen(config_path, "r");
    if (!file) {
        perror("fopen");
        return -1;
    }

    char line[512];
    size_t count = 0;

    while (fgets(line, sizeof(line), file) && count < max_files) {
        line[strcspn(line, "\r\n")] = '\0';

        if (strlen(line) == 0) continue;

        strncpy(watched_files[count], line, max_path_len);
        watched_files[count][max_path_len - 1] = '\0';
        count++;
    }

    fclose(file);
    if (loaded_count_out) {
        *loaded_count_out = count;
    }

    return 0;
}