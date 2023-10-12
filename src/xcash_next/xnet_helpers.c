#include "xnet_helpers.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "define_macros.h"
#include "variables.h"

#define TRIGGER_TIMEOUT_SECONDS 0.5


// the helper just tries to open the socket just to speed up shutdown process
int poke_dpops_port(void) {
    int sockfd;
    struct sockaddr_in server_addr;
    fd_set fdset;
    struct timeval tv;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        return -1;
    }

    // Set socket to non-blocking mode
    fcntl(sockfd, F_SETFL, O_NONBLOCK);

    // Set up the server details
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(XCASH_DPOPS_PORT);
    if (inet_pton(AF_INET, XCASH_DPOPS_delegates_IP_address, &server_addr.sin_addr) <= 0) {
        close(sockfd);
        return -1;
    }

    // Start connecting to the server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        if (errno != EINPROGRESS) {
            close(sockfd);
            return -1;
        }
    }

    // Use select to wait for the connection to complete or timeout
    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);
    tv.tv_sec = (int)TRIGGER_TIMEOUT_SECONDS;
    tv.tv_usec = (TRIGGER_TIMEOUT_SECONDS - tv.tv_sec) * 1000000;  // remainder in microseconds

    if (select(sockfd + 1, NULL, &fdset, NULL, &tv) == 1) {
        int so_error;
        socklen_t len = sizeof(so_error);

        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);

        if (so_error == 0) {
            // printf("Connected to %s:%d\n", IP, PORT);
        } else {
            // Error during connection
            // fprintf(stderr, "Connection failed: %s\n", strerror(so_error));
            close(sockfd);
            return -1;
        }
    } else {
        // Connection timed out
        close(sockfd);
        return -1;
    }

    // Sleep for 0.5 seconds (optional)
    usleep(100000); // 500000 microseconds = 0.5 seconds

    // Close the connection
    close(sockfd);

    return 0;
}
