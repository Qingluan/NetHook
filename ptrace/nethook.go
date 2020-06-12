package ptrace

// +build cgo,!netgo
/* C code */

/*
#include <sys/socket.h>

typedef unsigned long long uint64_t;
struct socket_info {
	pid_t pid;
	uint64_t magic_fd;
	int fd;
	int domain;
	int type;
};

*/
// import "C"
