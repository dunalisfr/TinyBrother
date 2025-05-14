#ifndef __FILE_OPEN_H
#define __FILE_OPEN_H

    #define MAX_WATCHED_FILES 100
    #define MAX_PATH_LEN 256

    #include <stdlib.h>
    
    int load_watched_files(const char *config_path, char watched_files[][256],size_t max_files, size_t max_path_len, size_t *loaded_count_out);

#endif /* __FILE_OPEN_H  */
