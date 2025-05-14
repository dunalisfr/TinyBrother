#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <unistd.h>

#include "file_open_bpf.skel.h" 

#include "process.h"
#include "common.h"
#include "file_open.h"

static volatile bool exiting = false;

const char *log_path = "./file_event.log";
const char *cnf_path = "./file_event.cnf";
char watched_files[MAX_WATCHED_FILES][MAX_PATH_LEN];
size_t watched_files_count = 0;

void handle_signal(int sig) {
    exiting = true;
}

int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct file_event *event = data;
    struct process_user_info info;
    char cmdline[MAX_CMDLINE_LEN];
    char access = event->flags & 3;
    char read_access = (access == 0 || access == 2);
    char write_access = (access == 1 || access == 2);

    bool is_watched = false;
    for (size_t i = 0; i < watched_files_count; ++i) {
        if (strncmp(event->filename, watched_files[i],MAX_PATH_LEN) == 0) {
            is_watched = true;
            break;
        }
    }

    if (!is_watched) {
        return 0;
    }
    
    get_process_cmdline(event->pid,cmdline,MAX_CMDLINE_LEN);
    get_username_from_pid(event->pid,&info,MAX_STATUS_LEN);

    if(event->pid != getpid()){
        FILE *log = fopen(log_path, "a");
        if (log) {
            fprintf(log, "{\"type\": \"file_open\" , \"pid\": %u , \"com\": \"%s\" , \"file\": \"%s\",\"read_mode\": %s,\"write_mode\": %s,\"cmdline\": \"%s\", \"userid\":%u, \"user\": \"%s\"}\n",
                    event->pid, event->comm, event->filename,read_access? "true" : "false",write_access? "true" : "false",cmdline,info.uid,info.name);
            fclose(log);
        } else {
            fclose(log);
            perror("Failed to open log file");
        }
    }
    return 0;
}

void handle_lost_events(void *ctx, int lost) {
    fprintf(stderr, "Lost %d events\n", lost);
}

int event_listener() {
    struct file_open_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;


    skel = file_open_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = file_open_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        file_open_bpf__destroy(skel);
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        file_open_bpf__destroy(skel);
        return 1;
    }

    printf("Listening for open file events... Press Ctrl+C to exit.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            fprintf(stderr, "Ring buffer polling error: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    file_open_bpf__destroy(skel);
    return 0;
}

void print_usage(const char *program_name) {
    fprintf(stderr,
        "Usage: %s [--file-open-logs <path>] [--file-open-cnf <path>]\n"
        "\nRequirements:\n"
        "  - The eBPF program (BNF module) 'file_event' must be attached to the kernel.\n"
        "  - This program must be run with root privileges (e.g., using sudo).\n"
        "\n"
        "Options:\n"
        "  --file-open-logs <path>   Path to the log file where file access events will be recorded.\n"
        "                            Default: ./file_event.log\n"
        "\n"
        "  --file-open-cnf <path>    Path to the configuration file listing files to monitor.\n"
        "                            This file must contain one absolute file path per line.\n"
        "                            Maximum: 100 files, each path up to 256 characters.\n"
        "                            Example:\n"
        "                                /etc/passwd\n"
        "                                /etc/shadow\n"
        "                            Default: ./file_event.cnf\n"
        "\n"
        "  --help                    Display this help message.\n",
        program_name
    );
}


int main(int argc, char *argv[]) {

    for (int i = 1; i < argc; ++i) {
        if (strncmp(argv[i], "--file-open-logs", 19) == 0 && i + 1 < argc) {
            log_path = argv[++i];
        } else if (strncmp(argv[i], "--file-open-cnf", 19) == 0 && i + 1 < argc) {
            cnf_path = argv[++i];
        } else if (strncmp(argv[i], "--help", 7) == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown or incomplete option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Root privileges required.\n");
        return EXIT_FAILURE;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    if (load_watched_files(cnf_path, watched_files, MAX_WATCHED_FILES, MAX_PATH_LEN, &watched_files_count) != 0) {
        fprintf(stderr, "Failed to load configuration file.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    if( watched_files_count == 0) {
        fprintf(stderr, "No files to monitore\n");
        return 0;
    }

    return event_listener();
}

