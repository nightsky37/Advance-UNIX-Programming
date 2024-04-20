#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>

int main(int argc, char *argv[])
{
    int opt;
    char *sopath = "./logger.so";
    char *outpath = NULL;
    // FILE *config = fopen(argv[1], "r");
    char *config_path = argv[1];

    while ((opt = getopt(argc, argv, "p:o:")) != -1)
    {
        switch (opt)
        {
        case 'p':
            if (optarg)
            {
                sopath = strdup(optarg);
            }
            break;
        case 'o':
            if (optarg)
            {
                outpath = strdup(optarg);
            }
            break;
        default:
            break;
        }
    }

    

    char CONFIG[] = "CONFIG_PATH";
    if(setenv(CONFIG, config_path, 1) == -1) {
        perror("setenv failed:");
    }

    char out[] = "OUTPATH";    
    if(outpath != NULL) {
        if(setenv(out, outpath, 1) == -1) {
            perror("setenv failed:");
        }
    }

    
    char LD[] = "LD_PRELOAD=";
    char *cmd = malloc(strlen(LD)+strlen(sopath)+strlen(argv[++optind])+10);
    cmd = strcat(cmd, LD);
    strcat(cmd, sopath);
    strcat(cmd, " ");
    strcat(cmd, argv[optind]);
    // printf("cmd=%s\n", cmd);

    char connect[] = "EXTARGS";
    char *addrs = malloc(1000);
    while(argv[++optind] != NULL) {
        addrs = strcat(addrs, argv[optind]);
        strcat(addrs, " ");
    }
    if(addrs != NULL) {
        if(setenv(connect, addrs, 1) == -1) {
            perror("setenv failed:");
        }
    }
    
    strcat(cmd, " ");
    strcat(cmd, addrs);
    system(cmd);
    free(cmd);
}
