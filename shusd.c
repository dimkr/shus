#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <signal.h>
#include <ctype.h>
#include <locale.h>
#include <sys/wait.h>
#include <paths.h>
#include <assert.h>
#include <pwd.h>

#include "common.h"

/* the usage messge */
#define USAGE "Usage: "PACKAGE" [PORT] ROOT\n"

/* the number of elements in an array */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

/* the listening backlog size */
#define BACKLOG_SIZE (128)

/* the server banner */
#define SERVER_BANNER PACKAGE"/"VERSION

/* the minimum size of a valid request, in bytes */
#define MIN_REQUEST_SIZE (sizeof(char) * STRLEN("GET / HTTP/1.1\r\nHost: *"))

/* the maximum size of a request */
#define MAX_REQUEST_LENGTH (4096)

/* the MIME-type of files with an unrecognized extension */
#define FALLBACK_MIME_TYPE "application/octet-stream"

/* the MIME-type matching a file name extension */
typedef struct {
	const char *extension;
	const char *type;
} mime_type_t;

/* a HTTP status code */
typedef struct {
	const char *text;
	size_t length;
} status_code_t;

#define STATUS_CODE(x) { x, STRLEN(x) }

static const mime_type_t g_mime_types[] = {
	{ "html", "text/html" },
	{ "css", "text/css" },
	{ "png", "image/png" },
	{ "txt", "text/plain" }
};

static const status_code_t g_status_codes[] = {
	STATUS_CODE("200 OK"),
	STATUS_CODE("400 Bad Request"),
	STATUS_CODE("404 Not Found"),
	STATUS_CODE("411 Length Required"),
	STATUS_CODE("413 Request Entity Too Large"),
	STATUS_CODE("415 Unsupported Media Type"),
	STATUS_CODE("500 Internal Server Error"),
	STATUS_CODE("505 HTTP Version Not Supported")
};

#define STATUS_CODE_OK				&g_status_codes[0]
#define STATUS_CODE_BAD_REQUEST		&g_status_codes[1]
#define STATUS_CODE_NOT_FOUND		&g_status_codes[2]
#define STATUS_CODE_TOO_SMALL		&g_status_codes[3]
#define STATUS_CODE_TOO_BIG			&g_status_codes[4]
#define STATUS_CODE_BAD_MIME_TYPE	&g_status_codes[5]
#define STATUS_CODE_INTERNAL_ERROR	&g_status_codes[6]
#define STATUS_CODE_BAD_PROTOCOL	&g_status_codes[7]

static const char *_get_mime_type(const char *extension) {
	/* a loop index */
	unsigned int i = 0;

	/* find the MIME-type matching the extension */
	for ( ; ARRAY_SIZE(g_mime_types) > i; ++i) {
		if (0 == strcmp(g_mime_types[i].extension, extension)) {
			return g_mime_types[i].type;
		}
	}

	return FALLBACK_MIME_TYPE;
}

bool _get_time(char *buffer) {
	/* the current time, in broken-down form */
	struct tm now_parsed = {0};

	/* the trailing line break index */
	size_t index = 0;

	/* the current time */
	time_t now = {0};

	now = time(NULL);

    if (NULL == gmtime_r(&now, &now_parsed)) {
    	return false;
    }

    /* convert the current time to a string */
	if (NULL == asctime_r(&now_parsed, buffer)) {
		return false;
	}

	/* trim the terminating line break */
	index = strlen(buffer) - 1;
	assert('\n' == buffer[index]);
	buffer[index] = '\0';

	return true;
}

bool _send_response(char *request, const ssize_t size, FILE *log_file) {
	/* the sent file path */
	char path[PATH_MAX] = {'\0'};

	/* the sent file attributes */
	struct stat attributes = {0};

	/* the current time */
	char now[26] = {'\0'};

	/* the offset passed to sendfile() */
	off_t offset = 0;

	/* a file descriptor */
	int fd = (-1);

	/* the return value of snprintf() and fprintf() */
	int length = 0;

	/* the return value */
	bool result = false;

	/* the sent file MIME-type */
	const char *mime_type = NULL;

	/* the status code */
	const status_code_t *status_code = STATUS_CODE_INTERNAL_ERROR;

	/* the requested URL */
	char *url = NULL;

	/* the HTTP version */
	char *protocol = NULL;

	/* the request headers */
	char *headers = NULL;

	/* the "Host" header */
	char *host = NULL;

	/* a line break in the headers */
	char *line_break = NULL;

	/* the file name extension */
	const char *extension = NULL;

	/* get the current time */
	if (false == _get_time(now)) {
		goto send_response;
	}

	/* check whether the request is too small */
	if (MIN_REQUEST_SIZE > size) {
		status_code = STATUS_CODE_TOO_SMALL;
		goto send_response;
	}

	/* check whether the request is too big */
	if ((sizeof(char) * MAX_REQUEST_LENGTH) <= size) {
		status_code = STATUS_CODE_TOO_BIG;
		goto send_response;
	}

	/* make sure the request is a GET one */
	if (0 != strncmp(request, "GET /", STRLEN("GET /"))) {
		status_code = STATUS_CODE_BAD_REQUEST;
		goto send_response;
	}

	/* locate the URL and make sure it begins with / */
	url = request + STRLEN("GET");
	url[0] = '\0';
	++url;
	if ('/' != url[0])  {
		status_code = STATUS_CODE_BAD_REQUEST;
		goto send_response;
	}

	/* locate the protocol */
	protocol = strchr(url, ' ');
	if (NULL == protocol) {
		status_code = STATUS_CODE_BAD_REQUEST;
		goto send_response;
	}

	/* terminate the URL */
	protocol[0] = '\0';
	++protocol;

	/* make sure the URL doesn't contain relative paths */
	if (NULL != strstr(url, "./")) {
		status_code = STATUS_CODE_BAD_REQUEST;
		goto send_response;
	}

	/* locate the headers */
	headers = protocol + STRLEN("HTTP/1.1\r\n");
	if (0 == isupper(headers[0])) {
		status_code = STATUS_CODE_BAD_REQUEST;
		goto send_response;
	}

	/* locate the "Host" header */
	host = strstr(headers, "Host: ");
	if (NULL == host) {
		status_code = STATUS_CODE_BAD_REQUEST;
		goto send_response;
	}
	host += STRLEN("Host: ");
	if (0 == isalnum(host[0])) {
		status_code = STATUS_CODE_BAD_REQUEST;
		goto send_response;
	}

	/* terminate the "Host" header */
	line_break = strstr(host, "\r\n");
	if (NULL == line_break) {
		status_code = STATUS_CODE_BAD_REQUEST;
		goto send_response;
	}
	line_break[0] = '\0';

	/* make sure the protocol is HTTP 1.0 or 1.1 */
	if ((0 != strncmp("HTTP/1.0\r\n", protocol, STRLEN("HTTP/1.0\r\n"))) &&
	    (0 != strncmp("HTTP/1.1\r\n", protocol, STRLEN("HTTP/1.1\r\n")))) {
		status_code = STATUS_CODE_BAD_PROTOCOL;
		goto send_response;
	}

	/* locate the requested file extension */
	extension = strrchr(url, '.');

	/* format the file path and obtain its MIME-type */
	if (NULL != extension) {
		++extension;
		length = snprintf(path, sizeof(path), "%s%s", host, url);
		mime_type = _get_mime_type(extension);
	} else {
		length = snprintf(path, sizeof(path), "%s%s/"INDEX_PAGE, host, url);
		mime_type = _get_mime_type(INDEX_EXTENSION);
	}
	if (sizeof(path) <= length) {
		status_code = STATUS_CODE_TOO_BIG;
		goto send_response;
	}
	if (0 > length) {
		status_code = STATUS_CODE_BAD_REQUEST;
		goto send_response;
	}

	/* get the file size and open it - upon failure, do not disclose the
	 * reason */
	if (0 == stat(path, &attributes)) {
		fd = open(path, O_RDONLY);
	} else {
		if (ENOENT == errno) {
			if (0 == stat(url, &attributes)) {
				fd = open(url, O_RDONLY);
			}
		}
		status_code = STATUS_CODE_INTERNAL_ERROR;
		goto send_response;
	}
	if (-1 != fd) {
		status_code = STATUS_CODE_OK;
	} else {
		if (ENOENT == errno) {
			status_code = STATUS_CODE_NOT_FOUND;
		} else {
			status_code = STATUS_CODE_INTERNAL_ERROR;
		}
	}

send_response:
	/* log the request details */
	if (NULL == host) {
		host = "?";
	}
	if (NULL == url) {
		url = "?";
	}
	if ('\0' != now[0]) {
		length = fprintf(log_file,
		                 "[%s] GET %s %s -> %s\n",
		                 now,
		                 host,
		                 url,
		                 status_code->text);
	} else {
		length = fprintf(log_file,
		                 "[?] GET %s%s -> %s\n",
		                 host,
		                 url,
		                 status_code->text);
	}
	if (0 < length) {
		result = true;
	}

	/* send mandatory headers common to all response types */
	if (0 > printf("HTTP/1.1 %s\r\n" \
	               "Connection: close\r\n" \
	               "Server: "SERVER_BANNER"\r\n",
	               status_code->text)) {
		goto close_file;
	}

	/* if the date was retrieved successfully, send it */
	if ('\0' != now[0]) {
		if (0 > printf("Date: %s\r\n", now)) {
			goto close_file;
		}
	}

	/* if the file was opened, send its type, size and contents */
	if (-1 != fd) {
		if (0 > printf("Content-Length: %zd\r\n"
		               "Content-Type: %s\r\n" \
		               "\r\n",
		               (size_t) attributes.st_size,
		               mime_type)) {
			goto close_file;
		}

		if ((ssize_t) attributes.st_size != sendfile(
		                                         STDOUT_FILENO,
		                                         fd,
		                                         &offset,
		                                         (size_t) attributes.st_size)) {
			goto close_file;
		}
	} else {
		/* otherwise, send the status code as the response content */
		if (0 > printf("Content-Length: %zd\r\n" \
		               "\r\n" \
		               "%s",
		               status_code->length,
		               status_code->text)) {
			goto close_file;
		}
	}

close_file:
	/* close the file */
	if (-1 != fd) {
		(void) close(fd);
	}

	return result;
}

int main(int argc, char *argv[]) {
	/* a raw request */
	char request[MAX_REQUEST_LENGTH] = {'\0'};

	/* resolving hints for getaddrinfo() */
	struct addrinfo hints = {0};

	/* the client address */
	struct sockaddr client_address = {0};

	/* the process signal mask */
	sigset_t signal_mask = {{0}};

	/* a received signal */
	siginfo_t received_signal = {0};

	/* the request size */
	ssize_t request_size = (-1);

	/* the client address size */
	socklen_t address_size = 0;

	/* the listening socket */
	int listening_socket = (-1);

	/* a client socket */
	int client = (-1);

	/* a file descriptor */
	int fd = (-1);

	/* the exit code */
	int exit_code = EXIT_FAILURE;

	/* 1 */
	int one = 1;

	/* the listening socket flags */
	int flags = 0;

	/* a signal received when a client connects to the server */
	int io_signal = 0;

	/* the exit status of a child process */
	int status = 0;

	/* a child process ID */
	pid_t pid = (-1);

	/* the listening address */
	struct addrinfo *listening_address = NULL;

	/* the log file */
	FILE *log_file = NULL;

	/* the listening port */
	const char *port = NULL;

	/* the server root directory */
	const char *root = NULL;

	/* the process owner */
	struct passwd *owner = NULL;

	/* parse the command-line */
	switch (argc) {
		case 2:
			port = "80";
			root = argv[1];
			break;

		case 3:
			port = argv[1];
			root = argv[2];
			break;

		default:
			PRINT(USAGE);
			goto end;
	}

	/* pick the minimum real-time signal */
	io_signal = SIGRTMIN;

	/* block io_signal, SIGCHLD and SIGTERM signals */
	if (-1 == sigemptyset(&signal_mask)) {
		goto end;
	}
	if (-1 == sigaddset(&signal_mask, io_signal)) {
		goto end;
	}
	if (-1 == sigaddset(&signal_mask, SIGCHLD)) {
		goto end;
	}
	if (-1 == sigaddset(&signal_mask, SIGTERM)) {
		goto end;
	}
	if (-1 == sigprocmask(SIG_SETMASK, &signal_mask, NULL)) {
		goto end;
	}

	/* get the process owner UID */
	owner = getpwnam(USER);
	if (NULL == owner) {
		goto end;
	}

	/* set the locale to the portable one, to force consistency in ctype.h
	 * functions */
	if (NULL == setlocale(LC_ALL, "")) {
		goto end;
	}

	/* resolve the listening address */
	hints.ai_flags = AI_PASSIVE | AI_V4MAPPED | AI_ADDRCONFIG;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_addr = NULL;
	hints.ai_canonname = NULL;
	hints.ai_next = NULL;
	if (0 != getaddrinfo(NULL, port, &hints, &listening_address)) {
		goto end;
	}

	/* create a socket */
	listening_socket = socket(listening_address->ai_family,
	                          listening_address->ai_socktype,
	                          listening_address->ai_protocol);
	if (-1 == listening_socket) {
		goto free_address;
	}

	/* get the listening socket flags */
	flags = fcntl(listening_socket, F_GETFL);
	if (-1 == flags) {
		goto close_socket;
	}

	/* make it possible to listen on the same address again */
	if (-1 == setsockopt(listening_socket,
	                     SOL_SOCKET,
	                     SO_REUSEADDR,
	                     (void *) &one,
	                     sizeof(one))) {
		goto close_socket;
	}

	/* bind the socket */
	if (-1 == bind(listening_socket,
	               listening_address->ai_addr,
	               listening_address->ai_addrlen)) {
		goto close_socket;
	}

	/* start listening */
	if (-1 == listen(listening_socket, BACKLOG_SIZE)) {
		goto close_socket;
	}

	/* set the I/O signal */
	if (-1 == fcntl(listening_socket, F_SETSIG, io_signal)) {
 		goto close_socket;
	}

	/* enable non-blocking, asynchronous I/O */
	if (-1 == fcntl(listening_socket, F_SETFL, flags | O_NONBLOCK | O_ASYNC)) {
		goto close_socket;
	}

	/* create a child process */
	switch (fork()) {
		case (-1):
			goto close_socket;

		case 0:
			break;

		default:
			(void) close(listening_socket);
			freeaddrinfo(listening_address);
			exit(EXIT_SUCCESS);
	}

	/* make the child process a session leader */
	if (((pid_t) -1) == setsid()) {
		goto close_socket;
	}

	/* create a child process, again */
	switch (fork()) {
		case (-1):
			goto close_socket;

		case 0:
			break;

		default:
			(void) close(listening_socket);
			freeaddrinfo(listening_address);
			exit(EXIT_SUCCESS);
	}

	/* redirect all standard pipes to /dev/null */
	if (-1 == close(STDIN_FILENO)) {
		goto close_socket;
	}
	if (-1 == open(_PATH_DEVNULL, O_RDONLY)) {
		goto close_socket;
	}
	if (-1 == close(STDOUT_FILENO)) {
 		goto close_socket;
	}
	if (-1 == open(_PATH_DEVNULL, O_WRONLY)) {
		goto close_socket;
	}
	if (-1 == close(STDERR_FILENO)) {
		goto close_socket;
	}
	fd = dup(STDIN_FILENO);
	if (STDERR_FILENO != fd) {
		(void) close(fd);
		goto close_socket;
	}

	/* set the file permissions mask */
	(void) umask(0);

	/* change the file descriptor ownership */
	if (-1 == fcntl(listening_socket, F_SETOWN, getpid())) {
		goto close_socket;
	}

	/* open the log file */
	log_file = fopen(LOG_PATH, "a");
	if (NULL == log_file) {
		goto close_socket;
	}

	/* change the working directory to the server root */
	if (-1 == chroot(root)) {
		goto close_log;
	}
	if (-1 == chdir("/")) {
		goto close_log;
	}

	/* change the process owner */
	if (-1 == setuid(owner->pw_uid)) {
		goto end;
	}
	if (-1 == seteuid(owner->pw_uid)) {
		goto end;
	}

	/* disable printf() buffering, to ensure the child process output is written
	 * in the right order */
	setbuf(stdout, NULL);

	do {
		/* wait for a signal */
		if (-1 == sigwaitinfo(&signal_mask, &received_signal)) {
			goto close_log;
		}
		switch (received_signal.si_signo) {
			case SIGTERM:
				goto success;

			case SIGCHLD:
				/* if a child process exited with an error code, stop */
				if (pid != waitpid(received_signal.si_pid, &status, WNOHANG)) {
					if (EXIT_SUCCESS != WEXITSTATUS(status)) {
						goto close_log;
					}
				}
				break;

			default:
				if (io_signal != received_signal.si_signo) {
					goto close_log;
				}
		}

		/* accept a client */
		client = accept(listening_socket, &client_address, &address_size);
		if (-1 == client) {
			if ((EAGAIN == errno) || (ECONNABORTED == errno)) {
				continue;
			}
			goto close_log;
		}

		/* enable the TCP_CORK flag, to make the response more efficient */
		one = 1;
		if (-1 == setsockopt(client,
		                     IPPROTO_TCP,
		                     TCP_CORK,
		                     (void *) &one,
		                     sizeof(one))) {
			goto close_socket;
		}

		/* spawn a child process */
		pid = fork();
		switch (pid) {
			case (-1):
				goto close_log;

			case 0:
				/* under the child process, free all unneeded resources */
				(void) close(listening_socket);
				freeaddrinfo(listening_address);

				/* receive the request */
				request_size = recv(client,
				                    (void *) request,
				                    sizeof(request),
				                    0);
				switch (request_size) {
					case (-1):
					case 0:
						exit_code = EXIT_SUCCESS;
						goto terminate;
				}

				/* close the standard output pipe */
				if (-1 == close(STDOUT_FILENO)) {
					goto terminate;
				}

				/* redirect all output to the socket */
				fd = dup(client);
				if (STDOUT_FILENO != fd) {
					(void) close(fd);
					goto terminate;
				}

				/* terminate the request */
				request[request_size] = '\0';

				/* respond to it */
				if (true == _send_response(request, request_size, log_file)) {
					exit_code = EXIT_SUCCESS;
				}

terminate:
				/* disconnect the client */
				(void) close(client);

				/* close the log file */
				(void) fclose(log_file);

				exit(exit_code);

			default:
				/* close the client socket */
				(void) close(client);
		}
	} while (1);

success:
	exit_code = EXIT_SUCCESS;

close_log:
	/* close the log file */
	(void) fclose(log_file);

close_socket:
	/* close the listening socket */
	(void) close(listening_socket);

free_address:
	/* free the listening address */
	freeaddrinfo(listening_address);

end:
	return exit_code;
}
