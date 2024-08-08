#include "download.h"
/*****************************************************************************/
/* parse input string and create TCP Socket -> SOCK_STREAM                   */
/*****************************************************************************/
int parse(char *input, struct URL *url) {

    regex_t regex;
    regcomp(&regex, BAR, 0);
    if (regexec(&regex, input, 0, NULL, 0)) return -1;

    regcomp(&regex, AT, 0);
    if (regexec(&regex, input, 0, NULL, 0) != 0) { //ftp://<host>/<url-path>  
        sscanf(input, HOST_REGEX, url->host);
        strcpy(url->user, DEFAULT_USER);
        strcpy(url->password, DEFAULT_PASSWORD);

    } else { // ftp://[<user>:<password>@]<host>/<url-path>

        sscanf(input, HOST_AT_REGEX, url->host);
        sscanf(input, USER_REGEX, url->user);
        sscanf(input, PASS_REGEX, url->password);
    }

    sscanf(input, RESOURCE_REGEX, url->resource);
    strcpy(url->file, strrchr(input, '/') + 1);

    struct hostent *h;
    if (strlen(url->host) == 0) return -1;
    if ((h = gethostbyname(url->host)) == NULL) {
        printf("Invalid hostname '%s'\n", url->host);
        exit(-1);
    }
    strcpy(url->ip, inet_ntoa(*((struct in_addr *) h->h_addr)));

    return !(strlen(url->host) && strlen(url->user) && 
           strlen(url->password) && strlen(url->resource) && strlen(url->file));
}

int createSocket(char *ip, int port) {

    int sockfd;
    struct sockaddr_in server_addr;

    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip);  
    server_addr.sin_port = htons(port); 
    
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket()");
        exit(-1);
    }
    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("connect()");
        exit(-1);
    }
    
    return sockfd;
}

/*****************************************************************************/
/* connect to Socket with User and Password                                  */
/*****************************************************************************/
int authConn(const int socket, const char* user, const char* pass) {

    char userCommand[5+strlen(user)+1]; sprintf(userCommand, "user %s\n", user);
    char passCommand[5+strlen(pass)+1]; sprintf(passCommand, "pass %s\n", pass);
    char answer[MAX_LENGTH];
    
    write(socket, userCommand, strlen(userCommand));
    
    int resp = readResponse(socket, answer);
    printf("%s\n", answer);

    if (resp != SV_READY4PASS) {
        printf("Unknown user '%s'. Abort.\n", user);
        exit(-1);
    }
    
    write(socket, passCommand, strlen(passCommand));

    
    resp = readResponse(socket, answer);
    printf("%s\n", answer);

    return resp;
}

/*****************************************************************************/
/* set Socket in passive mode                                                */
/*****************************************************************************/
int passiveMode(const int socket, char *ip, int *port) {

    char answer[MAX_LENGTH];
    int ip1, ip2, ip3, ip4, port1, port2;
    write(socket, "pasv\n", 5);
    
    int resp = readResponse(socket, answer);
    printf("%s\n", answer);

    if (resp != SV_PASSIVE) return -1;

    sscanf(answer, PASSIVE_REGEX, &ip1, &ip2, &ip3, &ip4, &port1, &port2);
    *port = port1 * 256 + port2;
    sprintf(ip, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);

    return SV_PASSIVE;
}


/*****************************************************************************/
/* read data from Socket                                                     */
/*****************************************************************************/
int readResponse(const int socket, char* buffer) {

    char byte;
    int index = 0, responseCode;
    ResponseState state = START;
    memset(buffer, 0, MAX_LENGTH);

    while (state != END) {
        
        read(socket, &byte, 1);
        switch (state) {
            case START:
                if (byte == ' ') state = SINGLE;
                else if (byte == '-') state = MULTIPLE;
                else if (byte == '\n') state = END;
                else buffer[index++] = byte;
                break;
            case SINGLE:
                if (byte == '\n') state = END;
                else buffer[index++] = byte;
                break;
            case MULTIPLE:
                if (byte == '\n') {
                    memset(buffer, 0, MAX_LENGTH);
                    state = START;
                    index = 0;
                }
                else buffer[index++] = byte;
                break;
            case END:
                break;
            default:
                break;
        }
    }

    sscanf(buffer, RESPCODE_REGEX, &responseCode);
    return responseCode;
}

/*****************************************************************************/
/* Get FILE                                                                  */
/*****************************************************************************/
int requestResource(const int socket, char *resource) {

    char fileCommand[5+strlen(resource)+1];
    char answer[MAX_LENGTH];

    sprintf(fileCommand, "retr %s\n", resource);

    write(socket, fileCommand, sizeof(fileCommand));

    int resp = readResponse(socket, answer);
    printf("%s\n", answer);
    
    return resp;
}

/*****************************************************************************/
/* Write Local File                                                          */
/*****************************************************************************/
int getResource(const int socketCmd, const int socketDta, char *fName) {

    FILE *fd = fopen(fName, "wb");
    if (fd == NULL) {
        printf("Error opening or creating local file '%s'\n", fName);
        exit(-1);
    }

    char buffer[MAX_LENGTH];
    int bytes;
    do {
        bytes = read(socketDta, buffer, MAX_LENGTH);
        if (fwrite(buffer, bytes, 1, fd) < 0) return -1;
    } while (bytes);
    fclose(fd);

    int resp = readResponse(socketCmd, buffer);
    printf("%s\n", buffer);

    return resp;
}

/*****************************************************************************/
/* close Sockets connection                                                  */
/*****************************************************************************/
int closeConnection(const int socketCmd, const int socketDta) {
    
    char answer[MAX_LENGTH];
    write(socketCmd, "quit\n", 5);
    
    int resp = readResponse(socketCmd, answer);
    printf("%s\n", answer);

    if(resp != SV_GOODBYE) return -1;
    return close(socketCmd) || close(socketDta);
}





/*****************************************************************************/
/* MAIN function                                                             */
/*****************************************************************************/
int main(int argc, char *argv[]) {

    // check function call sintax
    if (argc != 2) {
        printf("Usage: ./download ftp://[<user>:<password>@]<host>/<url-path>\n");
        exit(-1);
    } 

    // Create/initialize URL structure
    struct URL url;
    memset(&url, 0, sizeof(url));
    if (parse(argv[1], &url) != 0) {
        printf("Parse error. Usage: ./download ftp://[<user>:<password>@]<host>/<url-path>\n");
        exit(-1);
    }
    
    printf("Host: %s\nResource: %s\nFile: %s\nUser: %s\nPassword: %s\nIP Address: %s\n", url.host, url.resource, url.file, url.user, url.password, url.ip);

    // Connecto to FTP Port (control)
    char answer[MAX_LENGTH];  
    int socketCmd = createSocket(url.ip, FTP_PORT);
    if (socketCmd < 0 || readResponse(socketCmd, answer) != SV_READY4AUTH) {
        printf("Socket to '%s' and port %d failed\n", url.ip, FTP_PORT);
        exit(-1);
    }
    
    // FTP Login
    if (authConn(socketCmd, url.user, url.password) != SV_LOGINSUCCESS) {
        printf("Authentication failed with username = '%s' and password = '%s'.\n", url.user, url.password);
        exit(-1);
    }
    
    // Get FTP DATA Port
    int port;
    char ip[MAX_LENGTH];
    if (passiveMode(socketCmd, ip, &port) != SV_PASSIVE) {
        printf("Passive mode failed\n");
        exit(-1);
    }

    // Connect to FTP DATA Port?
    int socketDta = createSocket(ip, port);
    if (socketDta < 0) {
        printf("Socket to '%s:%d' failed\n", ip, port);
        exit(-1);
    }

    // check file
    if (requestResource(socketCmd, url.resource) != SV_READY4TRANSFER) {
        printf("Unknown resouce '%s' in '%s:%d'\n", url.resource, ip, port);
        exit(-1);
    }

    // get file
    if (getResource(socketCmd, socketDta, url.file) != SV_TRANSFER_COMPLETE) {
        printf("Error transfering file '%s' from '%s:%d'\n", url.file, ip, port);
        exit(-1);
    }

    // Close Sockets connection
    if (closeConnection(socketCmd, socketDta) != 0) {
        printf("Sockets close error\n");
        exit(-1);
    }
 
    return 0;
}
