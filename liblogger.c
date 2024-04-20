#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <libgen.h>
#include <dirent.h>
#include <fnmatch.h>
#include <sys/socket.h>
#include <netdb.h>

#define RULE_LEN 128
#define LINE_LEN 256
char openBlacklist[RULE_LEN][LINE_LEN];
char readBlacklist[LINE_LEN];
char writeBlacklist[RULE_LEN][LINE_LEN];
char connectBlacklist[RULE_LEN][LINE_LEN];
char addrBlacklist[RULE_LEN][LINE_LEN];
// typedef struct __dirstream DIR;

static FILE* (*fopen_old)(const char *path, const char *mode) = NULL;
static size_t (*fread_old)(void *ptr, size_t size, size_t nmemb, FILE *stream) = NULL;
static size_t (*fwrite_old)(const void *ptr, size_t size, size_t nmemb, FILE *stream) = NULL;
static int (*connect_old)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*getaddrinfo_old)(const char *node, const char *service,
                                const struct addrinfo *hints,
                                struct addrinfo **res) = NULL;
static int (*system_old)(const char *command) = NULL;

int open_idx = 0;
int write_idx = 0;
int connect_idx = 0;
int addr_idx = 0;
bool isReadConfig = false;
bool isOpenOutput = false;

void printBlackList() {
    for(int i=0; i<open_idx; i++) {
        printf("%s\n", openBlacklist[i]);
    }

    printf("%s\n", readBlacklist);
    for(int i=0; i<write_idx; i++) {
        printf("%s\n", writeBlacklist[i]);
    }
    for(int i=0; i<connect_idx; i++) {
        printf("%s\n", connectBlacklist[i]);
    }
    for(int i=0; i<addr_idx; i++) {
        printf("%s\n", addrBlacklist[i]);
    }
}


void readConfig() {
    char *config_path = getenv("CONFIG_PATH");
    int config = open(config_path, O_RDONLY);
    char blacklist[RULE_LEN][LINE_LEN];
    int list_idx = 0;
    if(config != -1) {
        char s, line[LINE_LEN];
        int idx=0;
        while(read(config, &s, sizeof(s)) != 0){
            if(s != '\n')
                line[idx++] = s;
            else {
                line[idx++] = '\0';
                strcpy(blacklist[list_idx++], line);                
                memset(line, '\0', sizeof(line));
                idx = 0;
            }              
        }
        strcpy(blacklist[list_idx++], line);
    }
    else
        perror("open");
    for(int i=0; i<list_idx; i++){        
        if(strcmp(blacklist[i++], "BEGIN open-blacklist") == 0){
            while (strcmp(blacklist[i], "END open-blacklist") != 0)
            {
                strcpy(openBlacklist[open_idx++], blacklist[i++]);
            }
            i++;      
        }
        if(strcmp(blacklist[i++], "BEGIN read-blacklist") == 0){
            strcpy(readBlacklist, blacklist[i++]);
            i++;
        }
        else i+=2;
        if(strcmp(blacklist[i++], "BEGIN write-blacklist") == 0){
            while (strcmp(blacklist[i], "END write-blacklist") != 0)
            {
                strcpy(writeBlacklist[write_idx++], blacklist[i++]);
            }
            i++;
        }
        if(strcmp(blacklist[i++], "BEGIN connect-blacklist") == 0){
            while (strcmp(blacklist[i], "END connect-blacklist") != 0)
            {
                strcpy(connectBlacklist[connect_idx++], blacklist[i++]);
            }
            i++;   
        }
        if(strcmp(blacklist[i++], "BEGIN getaddrinfo-blacklist") == 0){
            while (strcmp(blacklist[i], "END getaddrinfo-blacklist") != 0)
            {
                strcpy(addrBlacklist[addr_idx++], blacklist[i++]);
            }
            i++;   
        }
    }

    // printf("idx= %d, %d, %d, %d, %d", open_idx, write_idx, connect_idx, addr_idx, list_idx);
}


char *removeExtension(char* myStr) {
    char *retStr;
    char *lastExt;
    if (myStr == NULL) return NULL;
    if ((retStr = malloc (strlen (myStr) + 1)) == NULL) return NULL;
    strcpy (retStr, myStr);
    lastExt = strrchr (retStr, '.');
    if (lastExt != NULL)
        *lastExt = '\0';
    return retStr;
}

char *removeWildcard(const char* myStr) {
    char *retStr;
    char *lastExt;
    if (myStr == NULL) return NULL;
    if ((retStr = malloc (strlen (myStr) + 1)) == NULL) return NULL;
    strcpy (retStr, myStr);
    lastExt = strrchr (retStr, '*');
    if (lastExt != NULL)
        *lastExt = '\0';
    return retStr;
}

char *getRealPath(const char *path) {
    char *rlpath = malloc(1024);
    char *res = realpath(path, rlpath);
    if(res) {
        // printf("real path: %s\n", rlpath);
        return rlpath;
    }        
    else {
        //perror("realpath");
        return NULL;
    }
    
    return rlpath;
}

bool isInBlackList(const char *path, const char *api) {
    if(!isReadConfig) {
        readConfig();
        isReadConfig = true;
    }
    // printBlackList();

    if(strcmp(api, "open") == 0) {        
        char *rlPath = getRealPath(path);
        for(int i=0; i<open_idx; i++){
            char *tmp = removeWildcard(openBlacklist[i]);
            char *realBlklistPath = getRealPath(tmp);
            if(realBlklistPath != NULL && strstr(rlPath, realBlklistPath) == rlPath) {
                // printf("strstr=%s\n", strstr(rlPath, realBlklistPath));
                return true;
            }
        }
    }
    if(strcmp(api, "write") == 0) {        
        char *rlPath = getRealPath(path);
        for(int i=0; i<open_idx; i++) {
            char *tmp = removeWildcard(openBlacklist[i]);
            char *realBlklistPath = getRealPath(tmp);
            if(realBlklistPath != NULL && (rlPath, realBlklistPath) == rlPath) {
                // printf("strstr=%s\n", strstr(rlPath, realBlklistPath));
                return true;
            }
        }
        for(int i=0; i<write_idx; i++){
            char *tmp = removeWildcard(writeBlacklist[i]);
            char *realBlklistPath = getRealPath(tmp);
            if(strstr(rlPath, realBlklistPath) == rlPath) {
                // printf("strstr=%s\n", strstr(rlPath, realBlklistPath));
                return true;
            }
        }
    }
    if(strcmp(api, "read") == 0) {
        if(fnmatch(readBlacklist, path, 0) == 0) {
            return true;
        }
    }
    if(strcmp(api, "getaddrinfo") == 0) {
        for(int i=0; i<addr_idx; i++) {
            if(fnmatch(addrBlacklist[i], path, 0) == 0) {
                return true;
            }
        }
    }
    if(strcmp(api, "connect") == 0) {
        
        for(int i=0; i<connect_idx; i++){
            if(fnmatch(connectBlacklist[i], path, 0) == 0) {
                return true;
            }
        }
    }

    return false;
}

char *getFilepath(FILE *f) {
    int fd;
    char fd_path[255];
    char * filename = malloc(255);
    ssize_t n;

    fd = fileno(f);
    sprintf(fd_path, "/proc/self/fd/%d", fd);
    n = readlink(fd_path, filename, 255);
    if (n < 0)
        return NULL;
    filename[n] = '\0';
    return filename;
}


int isSymbolicLink(const char *filePath) {
    struct stat path_stat;
    if (lstat(filePath, &path_stat) != 0) {
        perror("Error retrieving file information");
        return -1; 
    }

    // Check if the file is a symbolic link
    return S_ISLNK(path_stat.st_mode);
}

FILE* fopen(const char *path, const char *mode) {
    char *outpath = getenv("OUTPATH");    
    fopen_old = dlsym(RTLD_NEXT, "fopen");
    FILE *output;
    if(!isOpenOutput) {
        output = fopen_old(outpath, "w");
        isOpenOutput = true;
    }
    else
        output = fopen_old(outpath, "a");

    // FILE *ftmp = fopen_old(path, mode);
    // char *filepath = getFilepath(ftmp);
    // printf("real file path=%s\n", filepath);


    // int isSymlink = isSymbolicLink(path);
    // if (isSymlink == -1) {
    //     perror("symlink failed");
    //     return NULL;
    // } 
    // else if (isSymlink) {
    //     printf("%s is a symbolic link\n", path);
    // }
    // else
    //     printf("%s is not a symbolic link\n", path);

    if(isInBlackList(path, "open")) {
        if(outpath != NULL){            
            fprintf(output, "[logger] fopen(\"%s\", \"%s\") = 0x0\n", path, mode);
        } 
        else {
            fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = 0x0\n", path, mode);
        }
        errno = EACCES;
        return NULL;
    }
    
    FILE *fp = fopen_old(path, mode);
    if(outpath != NULL) {
        fprintf(output, "[logger] fopen(\"%s\", \"%s\") = %p\n", path, mode, fp);
    }
    else {
        fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", path, mode, fp);
    }
    
    if(output != NULL)
        fclose(output);
        
    return fp;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    char *outpath = getenv("OUTPATH");    
    fopen_old = dlsym(RTLD_NEXT, "fopen");
    FILE *output;
    if(!isOpenOutput) {
        output = fopen_old(outpath, "w");
        isOpenOutput = true;
    }
    else
        output = fopen_old(outpath, "a");
    
    // if the file has been blocked by open block list already

    char *filepath = getFilepath(stream);
    char *filename = basename(filepath);
    filename = removeExtension(filename);

    char LogfileName[100];
    sprintf(LogfileName, "%d-%s-%s.log", getpid(), filename, "read");
    FILE *logfile = fopen_old(LogfileName, "a");

    int f = open(filepath, O_RDONLY);
    char buf[size * nmemb];
    size_t buf_idx = 0;
    if(f != -1) {
        char s;
        while(read(f, &s, sizeof(s)) != 0 && buf_idx < size * nmemb){
            if(s == '\n')
                continue;
            buf[buf_idx++] = s;
        }
        buf[buf_idx] = 0; // null-terminated
    }

    char *keyword = buf;
    
    if(isInBlackList(keyword, "read")) {
        if(outpath != NULL){            
            fprintf(output, "[logger] fread(\"%p\", %ld, %ld, %p) = 0\n", \
                    ptr, size, nmemb, stream);
        } 
        else {
            fprintf(stderr, "[logger] fread(\"%p\", %ld, %ld, %p) = 0\n", \
                    ptr, size, nmemb, stream);
        }
        // fprintf(logfile, "[logger] fread(\"%p\", %ld, %ld, %p) = 0\n", \
        //             ptr, size, nmemb, stream);
        // fclose(logfile);
        errno = EACCES;
        return 0;
    }

    fread_old = dlsym(RTLD_NEXT, "fread");
    size_t n = fread_old(ptr, size, nmemb, stream);
    if(outpath != NULL){
        fprintf(output, "[logger] fread(\"%p\", %ld, %ld, %p) = %ld\n", \
                ptr, size, nmemb, stream, n);
    } 
    else {
        fprintf(stderr, "[logger] fread(\"%p\", %ld, %ld, %p) = %ld\n", \
                ptr, size, nmemb, stream, n);
    } 
    // fprintf(logfile, "[logger] fread(\"%p\", %ld, %ld, %p) = 0\n", \
    //                 ptr, size, nmemb, stream);   
    fprintf(logfile, "%s\n", (char*) ptr);  // newline or not? it's ugly if no newline when appeding to logfile 
    fclose(logfile);
    if(output != NULL) 
        fclose(output);
    return n;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    char *outpath = getenv("OUTPATH");    
    fopen_old = dlsym(RTLD_NEXT, "fopen");
    
    FILE *output;
    if(!isOpenOutput) {
        output = fopen_old(outpath, "w");
        isOpenOutput = true;
    }
    else
        output = fopen_old(outpath, "a");

    // make the string print out "\n" instead of a newline
    char *str = (char*) ptr;
    char buf[1000];
    int buf_idx = 0;
    while(*str != '\0'){
        if(*str == '\n'){
            buf[buf_idx++] = '\\';
            buf[buf_idx++] = '\\n';
        }
        else
            buf[buf_idx++] = *str;
        str++;
    }
    buf[buf_idx] = 0;

    // if the file has been blocked by open block list already
    if(stream == NULL) {
        if(outpath != NULL){            
            fprintf(output, "[logger] fwrite(\"%s\", %ld, %ld, 0x0) = 0\n", \
                    buf, size, nmemb);
        } 
        else {
            fprintf(stderr, "[logger] fwrite(\"%s\", %ld, %ld, 0x0) = 0\n", \
                    buf, size, nmemb);
        }
        return 0;
    }

    char *filepath = getFilepath(stream);
    char *filename = basename(filepath);

    filename = removeExtension(filename);
    char LogfileName[100];
    sprintf(LogfileName, "%d-%s-%s.log", getpid(), filename, "write");
    FILE *logfile = fopen_old(LogfileName, "a");

    

    if(isInBlackList(filepath, "write")) {
        if(outpath != NULL){            
            fprintf(output, "[logger] fwrite(\"%s\", %ld, %ld, %p) = 0\n", \
                    buf, size, nmemb, stream);
        } 
        else {
            fprintf(stderr, "[logger] fwrite(\"%s\", %ld, %ld, %p) = 0\n", \
                    buf, size, nmemb, stream);
        }
        // fprintf(logfile, "[logger] fwrite(\"%s\", %ld, %ld, %p) = 0\n", \
        //             buf, size, nmemb, stream);
        // fclose(logfile);
        errno = EACCES;
        return 0;
    }
    fwrite_old = dlsym(RTLD_NEXT, "fwrite");
    size_t n = fwrite_old(ptr, size, nmemb, stream);

    // do something to wrote string and log to file
    char buf_to_log[size*nmemb];
    size_t idx = 0;
    char *tmp = (char*) ptr;
    while(*tmp != '\0' && idx < size*nmemb) {
        buf_to_log[idx++] = *tmp;
        tmp++;
    }
    buf_to_log[idx] = '\0';
    
    if(outpath != NULL){
        fprintf(output, "[logger] fwrite(\"%s\", %ld, %ld, %p) = %ld\n", \
                buf, size, nmemb, stream, n);
    } 
    else {
        fprintf(stderr, "[logger] fwrite(\"%s\", %ld, %ld, %p) = %ld\n", \
                buf, size, nmemb, stream, n);
    }

    // fprintf(logfile, "[logger] fwrite(\"%s\", %ld, %ld, %p) = 0\n", \
    //         buf, size, nmemb, stream);
    fprintf(logfile, "%s\n", buf_to_log);  // newline or not? it's ugly if no newline when appeding to logfile 
    fclose(logfile);

    if(output != NULL) 
        fclose(output);
    return n;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    char *outpath = getenv("OUTPATH");    
    fopen_old = dlsym(RTLD_NEXT, "fopen");
    
    FILE *output;
    if(!isOpenOutput) {
        output = fopen_old(outpath, "w");
        isOpenOutput = true;
    }
    else
        output = fopen_old(outpath, "a");
    
    // split addresses
    char *addr_list = getenv("EXTARGS");
    char *address = strtok(addr_list, " ");
    char *tmp = address;
    
    if(isInBlackList(address, "connect")) {
        if(outpath != NULL){            
            fprintf(output, "[logger] connect(%d, \"%s\", %d) = -1\n", \
                    sockfd, address, addrlen);
        } 
        else {
            fprintf(stderr, "[logger] connect(%d, \"%s\", %d) = -1\n", \
                    sockfd, address, addrlen);
        }
        errno = ECONNREFUSED;
        return -1;
    }

    connect_old = dlsym(RTLD_NEXT, "connect");
    int rvalue = connect_old(sockfd, addr, addrlen);

    if(outpath != NULL){            
        fprintf(output, "[logger] connect(%d, \"%s\", %d) = %d\n", \
                sockfd, address, addrlen, rvalue);
    } 
    else {
        fprintf(stderr, "[logger] connect(%d, \"%s\", %d) = %d\n", \
                sockfd, address, addrlen, rvalue);
    }

    if(output != NULL) 
        fclose(output);

    return rvalue;
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {  
    char *outpath = getenv("OUTPATH");    
    fopen_old = dlsym(RTLD_NEXT, "fopen");
    
    FILE *output;
    if(!isOpenOutput) {
        output = fopen_old(outpath, "w");
        isOpenOutput = true;
    }
    else
        output = fopen_old(outpath, "a");
    
    // split addresses
    // char *addr_list = getenv("CONNECT");
    // char *addr = strtok(addr_list, " ");

    if(isInBlackList(node, "getaddrinfo")) {
        if(outpath != NULL){            
            fprintf(output, "[logger] getaddrinfo(\"%s\", %p, %p, %p) = -1\n", \
                    node, service, hints, res);
        } 
        else {
            fprintf(stderr, "[logger] getaddrinfo(\"%s\", %p, %p, %p) = -1\n", \
                    node, service, hints, res);
        }
        return EAI_NONAME; 
    }

    getaddrinfo_old = dlsym(RTLD_NEXT, "getaddrinfo");
    int rvalue = getaddrinfo_old(node, service, hints, res);

    if(outpath != NULL){            
        fprintf(output, "[logger] getaddrinfo(\"%s\", %p, %p, %p) = %d\n", \
                node, service, hints, res, rvalue);
    } 
    else {
        fprintf(stderr, "[logger] getaddrinfo(\"%s\", %p, %p, %p) = %d\n", \
                node, service, hints, res, rvalue);
    }

    if(output != NULL) 
        fclose(output);

    return rvalue;
}

int system(const char *command) {
    char *outpath = getenv("OUTPATH");    
    fopen_old = dlsym(RTLD_NEXT, "fopen");
    FILE *output;
    if(!isOpenOutput) {
        output = fopen_old(outpath, "w");
        isOpenOutput = true;
    }
    else
        output = fopen_old(outpath, "a");

    system_old = dlsym(RTLD_NEXT, "system");
    int rvalue = system_old(command);

    if(outpath != NULL){            
        fprintf(output, "[logger] system(\"%s\") = %d\n", command, rvalue);
    } 
    else {
        fprintf(stderr, "[logger] system(\"%s\") = %d\n", command, rvalue);
    }

    if(output != NULL) 
        fclose(output);

    return rvalue; 
}
