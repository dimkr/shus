/*
 * this file is part of shus.
 *
 * Copyright (c) 2015 Dima Krasner
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <dirent.h>
#include <time.h>
#include <netdb.h>
#include <magic.h>
#include <sys/sendfile.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <errno.h>
#include <assert.h>
#include <paths.h>
#include <pwd.h>
#include <syslog.h>

#define USAGE "Usage: %s [SERVICE] DIR\n"
#define HANDLER_MAX (128)
#define BACKLOG (2 * HANDLER_MAX)
#define SEMAPHORE_NAME "/shusd.sem"
#define RECV_TIMEOUT (10)
#define SEND_TIMEOUT (15)
#define RAND_BUF_MIN_LEN (1024)
#define RAND_BUF_MAX_LEN (4096)

__attribute__((nonnull(1)))
static bool get_time(char *buf, const size_t len)
{
	struct tm tm;
	time_t now;

	now = time(NULL);

	if (NULL == gmtime_r(&now, &tm))
		return false;

	if (0 == strftime(buf, len, "%y/%m/%d %H:%M:%S", &tm))
		return false;

	return true;
}

__attribute__((nonnull(1, 3)))
static bool send_hdrs(FILE *fh,
                      const size_t len,
                      const char *type)
{
	char buf[sizeof("xx/xx/xx xx:xx:xx")];

	if (false == get_time(buf, sizeof(buf)))
		return false;

	if (0 == len) {
		if (0 > fprintf(fh,
		                "HTTP/1.1 200 OK\r\n" \
		                "Connection: close\r\n" \
		                "Date: %s\r\n" \
		                "Content-Type: %s\r\n" \
		                "\r\n",
		                buf,
		                type))
			return false;
	}
	else {
		if (0 > fprintf(fh,
		                "HTTP/1.1 200 OK\r\n" \
		                "Connection: close\r\n" \
		                "Date: %s\r\n" \
		                "Content-Type: %s\r\n" \
		                "Content-Length: %zu\r\n" \
		                "\r\n",
		                buf,
		                type,
		                len))
			return false;
	}

	return true;
}

__attribute__((nonnull(1, 3, 4)))
static bool send_file(FILE *fh,
                      const size_t len,
                      const char *type,
                      const char *path)
{
	off_t off;
	int in;
	bool ret = false;

	if (false == send_hdrs(fh, len, type))
		goto end;

	if (0 == len) {
		ret = true;
		goto end;
	}

	in = open(path, O_RDONLY);
	if (-1 == in)
		goto end;

	off = 0;
	if ((ssize_t) len == sendfile(fileno(fh), in, &off, len))
		ret = true;

	(void) close(in);

end:
	return ret;
}

__attribute__((nonnull(1)))
static int skip_hidden(const struct dirent *ent)
{
	if ('.' == ent->d_name[0])
		return 0;

	return 1;
}

__attribute__((nonnull(1, 2, 3)))
static bool send_index(FILE *fh, const char *url, const char *path)
{
	char index[PATH_MAX];
	struct stat stbuf;
	struct dirent **ents;
	int out;
	int i;
	int len;
	bool ret = false;

	/* if index.html exists, send it instead of listing the directory
	 * contents */
	len = snprintf(index, sizeof(index), "%s/index.html", path);
	if ((0 >= len) || (sizeof(index) <= len))
		goto end;

	if (-1 == stat(index, &stbuf)) {
		if (ENOENT != errno)
			goto end;
	}
	else {
		if (S_ISREG(stbuf.st_mode)) {
			if (false == send_file(fh,
			                       (size_t) stbuf.st_size,
			                       "text/html",
			                       index))
				goto end;
		}

		ret = true;
		goto end;
	}

	out = scandir(path, &ents, skip_hidden, alphasort);
	if (-1 == out)
		goto end;

	if (false == send_hdrs(fh, 0, "text/html"))
		goto end;

	if (0 >= fprintf(fh,
	                 "<!DOCTYPE HTML>\n" \
	                 "<html>\n" \
	                 "\t<head>\n" \
	                 "\t\t<meta charset=\"UTF-8\">\n" \
	                 "\t\t<title>Index of %s</title>\n" \
	                 "\t</head>\n" \
	                 "\t<body>\n" \
	                 "\t\t<h1>Index of %s</h1>\n" \
	                 "\t\t<ul>\n",
	                 url,
	                 url))
		goto free_ents;

	if (0 == strcmp("/", url)) {
		for (i = 0; out > i; ++i) {
			if (0 >= fprintf(fh,
			                 "\t\t\t<li><a href=\"/%s\">%s</a></li>\n",
			                 ents[i]->d_name,
			                 ents[i]->d_name))
				goto free_ents;
		}
	}
	else {
		for (i = 0; out > i; ++i) {
			if (0 >= fprintf(fh,
			                 "\t\t\t<li><a href=\"%s/%s\">%s</a></li>\n",
			                 url,
			                 ents[i]->d_name,
			                 ents[i]->d_name))
				goto free_ents;
		}
	}

	if (EOF == fputs("\t\t</ul>\n" \
	                 "\t</body>\n" \
	                 "</html>",
	                 fh))
		goto free_ents;

	ret = true;

free_ents:
	for (i = 0; out > i; ++i)
		free(ents[i]);
	free(ents);

end:
	return ret;
}

__attribute__((nonnull(1)))
static void send_random(FILE *fh)
{
	unsigned char buf[RAND_BUF_MAX_LEN];
	unsigned int seed;
	int len;
	int i;

	/* pick a random buffer size */
	seed = (unsigned int) time(NULL);
	len = RAND_BUF_MIN_LEN + \
	      (rand_r(&seed) % (1 + RAND_BUF_MAX_LEN - RAND_BUF_MIN_LEN));

	/* generate random data */
	for (i = 0; len > i; ++i)
		buf[i] = (unsigned char) (rand_r(&seed) % UCHAR_MAX);

	(void) fwrite((void *) buf, (size_t) len, 1, fh);
}

__attribute__((nonnull(1)))
static bool log_req(const struct sockaddr *peer, const char *url)
{
	char addr[INET6_ADDRSTRLEN];

	switch (peer->sa_family) {
		case AF_INET6:
			if (NULL == inet_ntop(AF_INET6,
			                      &(((struct sockaddr_in6*) peer)->sin6_addr),
			                      addr,
			                      sizeof(addr)))
				return false;
			break;

		case AF_INET:
			if (NULL == inet_ntop(AF_INET,
			                      &(((struct sockaddr_in*) peer)->sin_addr),
			                      addr,
			                      sizeof(addr)))
				return false;
			break;

		default:
			return false;
	}

	if (NULL == url)
		syslog(LOG_INFO, "received an invalid request from %s\n", addr);
	else {
		if ('\0' == url[0])
			syslog(LOG_INFO, "received a request for / from %s\n", addr);
		else
			syslog(LOG_INFO, "received a request for /%s from %s\n", url, addr);
	}

	return true;
}

__attribute__((nonnull(2)))
static const char *get_type(const magic_t mag, const char *url)
{
	const char *ext;

	ext = strrchr(url, '.');
	if (NULL != ext) {
		++ext;

		if (0 == strcmp("css", ext))
			return "text/css";

		if (0 == strcmp("js", ext))
			return "text/javascript";
	}

	return magic_file(mag, url);
}

__attribute__((nonnull(1, 3, 5)))
__attribute__((noreturn))
static void handle_conn(sem_t *sem,
                        const int conn,
                        const struct sockaddr *peer,
                        const magic_t mag,
                        const char *root,
                        const uid_t uid)
{
	char req[BUFSIZ];
	struct stat stbuf;
	const char *url = NULL;
	const char *type = "application/octet-stream";
	char *pos;
	FILE *fh = NULL;
	ssize_t len;
	int ret = EXIT_FAILURE;
	bool res;
	bool body;

	/* change the working directory */
	if (-1 == chroot(root))
		goto close_fd;
	if (-1 == chdir("/"))
		goto close_fd;

	/* change the process owner */
	if (-1 == setuid(uid))
		goto close_fd;
	if (-1 == seteuid(uid))
		goto close_fd;

	/* wrap the socket with a stdio stream */
	fh = fdopen(conn, "w");
	if (NULL == fh)
		goto close_fd;

	/* disable buffering, since we use TCP_CORK - we don't want two layers of
	 * buffering */
	setbuf(fh, NULL);

	/* lock the semaphore */
	if (-1 == sem_wait(sem))
		goto close_fh;

	/*
	 * we "punish" the client by sending variably-sized junk, if the request is
	 * invalid (e.g empty, another protocol, POST requests, path, traversal
	 * attempts using relative URLs, etc')
	 */

	/* receive the request */
	len = recv(conn, (void *) req, sizeof(req) - 1, 0);
	if (0 == len)
		goto punish;
	if (0 > len)
		goto unlock;
	req[len] = '\0';

	/* check the request type */
	if (0 == strncmp("GET ", req, 4)) {
		len = 4;
		body = true;
	}
	else {
		if (0 != strncmp("HEAD ", req, 5))
			goto punish;
		len = 5;
		body = false;
	}

	/* locate and terminate the URL */
	if ('\0' == req[len])
		goto punish;
	url = &req[len];
	pos = strchr(url, ' ');
	if (NULL == pos)
		goto punish;
	pos[0] = '\0';

	/* do not allow URLs that do not begin with / */
	if ('/' != url[0])
		goto punish;

	/* do not allow relative paths in the URL */
	if (('.' == url[0]) ||
	    (NULL != strstr(url, "./")) ||
	    (NULL != strstr(url, "/.")))
		goto punish;

	/* get the file type and size */
	if (-1 == stat(url, &stbuf)) {
		if (ENAMETOOLONG == errno)
			goto punish;
		goto unlock;
	}

	/* if it's a regular file, guess its type */
	if (!S_ISDIR(stbuf.st_mode)) {
		type = get_type(mag, url);
		if (NULL == type)
			goto unlock;
	}

	if (false == body) {
		if (S_ISDIR(stbuf.st_mode))
			res = send_hdrs(fh, 0, "text/html");
		else
			res = send_hdrs(fh, (size_t) stbuf.st_size, type);
	}
	else {
		if (S_ISDIR(stbuf.st_mode))
			res = send_index(fh, url, url);
		else
			res = send_file(fh, (size_t) stbuf.st_size, type, url);
	}
	if (true == res)
		ret = EXIT_SUCCESS;


	/* if we reached this point, the request is legitimate */
	goto unlock;

punish:
	send_random(fh);

unlock:
	(void) sem_post(sem);

close_fh:
	(void) shutdown(conn, SHUT_RDWR);
	(void) fclose(fh);

close_fd:
	/* fclose() already called close() */
	if (NULL == fh) {
		(void) shutdown(conn, SHUT_RDWR);
		(void) close(conn);
	}

	log_req(peer, url);

	exit(ret);
}

static bool daemonize(void)
{
	bool ret = false;
	int fd;

	/* create a child process */
	switch (fork()) {
		case (-1):
			goto end;

		case 0:
			break;

		default:
			exit(EXIT_SUCCESS);
	}

	/* make the child process a session leader */
	if (-1 == setsid())
		goto end;

	/* create a child process, again */
	switch (fork()) {
		case (-1):
			goto end;

		case 0:
			break;

		default:
			exit(EXIT_SUCCESS);
	}

	/* redirect all standard pipes to /dev/null */
	if (-1 == close(STDIN_FILENO))
		goto end;

	fd = open(_PATH_DEVNULL, O_RDONLY);
	if (-1 == fd)
		goto end;
	if (STDIN_FILENO != fd) {
		(void) close(fd);
		goto end;
	}

	if (-1 == close(STDOUT_FILENO))
		goto end;
	fd = open(_PATH_DEVNULL, O_WRONLY);
	if (STDOUT_FILENO != fd) {
		(void) close(fd);
		goto end;
	}

	if (STDERR_FILENO != dup2(STDOUT_FILENO, STDERR_FILENO))
		goto end;

	ret = true;

end:
	return ret;
}

int main(int argc, char *argv[])
{
	siginfo_t sig;
	struct sigaction act;
	struct addrinfo hints;
	struct sockaddr peer;
	struct timeval timeout;
	sigset_t mask;
	magic_t mag;
	sem_t *sem;
	const char *service;
	const char *root;
	struct addrinfo *addrs;
	struct passwd *user;
	pid_t pid;
	socklen_t len;
	int ret = EXIT_FAILURE;
	int shm;
	int fd;
	int conn;
	int rtsig;
	int flags;
	int one;

	switch (argc) {
		case 2:
			service = "http";
			root = argv[1];
			break;

		case 3:
			service = argv[1];
			root = argv[2];
			break;

		default:
			(void) fprintf(stderr, USAGE, argv[0]);
			goto end;
	}

	/* disable SIGCHLD signals */
	act.sa_handler = SIG_IGN;
	act.sa_flags = SA_NOCLDSTOP | SA_NOCLDWAIT;
	if (-1 == sigemptyset(&act.sa_mask))
		goto end;
	if (-1 == sigaction(SIGCHLD, &act, NULL))
		goto end;

	/* block SIGTERM, SIGINT and a realtime signal */
	if (-1 == sigemptyset(&mask))
		goto end;
	if (-1 == sigaddset(&mask, SIGTERM))
		goto end;
	if (-1 == sigaddset(&mask, SIGINT))
		goto end;
	rtsig = SIGRTMIN;
	if (-1 == sigaddset(&mask, rtsig))
		goto end;
	if (-1 == sigprocmask(SIG_BLOCK, &mask, NULL))
		goto end;

	/* get the user ID */
	user = getpwnam(USER);
	if (NULL == user)
		goto end;

	/* resolve the listening address */
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG | AI_V4MAPPED;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = AF_UNSPEC;
	hints.ai_protocol = 0;
	hints.ai_addrlen = 0;
	hints.ai_addr = NULL;
	hints.ai_canonname = NULL;
	hints.ai_next = NULL;
	if (0 != getaddrinfo(NULL, service, &hints, &addrs))
		goto end;

	/* open the magic database */
	mag = magic_open(MAGIC_SYMLINK | MAGIC_MIME_TYPE | MAGIC_ERROR);
	if (NULL == mag)
		goto free_addrs;
	if (-1 == magic_load(mag, NULL))
		goto close_mag;

	/* create a shared memory region */
	shm = shm_open(SEMAPHORE_NAME,
	               O_RDWR | O_CREAT | O_EXCL | O_TRUNC,
	               S_IRUSR | S_IWUSR);
	if (-1 == shm)
		goto close_mag;

	sem = (sem_t *) mmap(NULL,
	                     sizeof(sem_t),
	                     PROT_READ | PROT_WRITE,
	                     MAP_SHARED | MAP_ANONYMOUS,
	                     shm,
	                     0);
	if (MAP_FAILED == sem)
		goto free_shm;

	/* initialize a process-shared semaphore inside it */
	if (-1 == sem_init(sem, 1, HANDLER_MAX))
		goto unmap_shm;

	/* create a listening socket */
	fd = socket(addrs->ai_family, addrs->ai_socktype, addrs->ai_protocol);
	if (-1 == fd)
		goto destroy_sem;

	/* make it possible to listen on the same address again */
	one = 1;
	if (-1 == setsockopt(fd,
	                     SOL_SOCKET,
	                     SO_REUSEADDR,
	                     (void *) &one,
	                     sizeof(one)))
		goto close_fd;

	/* start listening */
	if (-1 == bind(fd, addrs->ai_addr, addrs->ai_addrlen))
		goto close_fd;

	if (-1 == listen(fd, BACKLOG))
		goto close_fd;

	/* enable asynchronous I/O, with a realtime signal instead of SIGIO */
	flags = fcntl(fd, F_GETFL);
	if (-1 == flags)
		goto close_fd;

	if (-1 == fcntl(fd, F_SETSIG, rtsig))
		goto close_fd;

	if (-1 == fcntl(fd, F_SETFL, flags | O_NONBLOCK | O_ASYNC))
		goto close_fd;

	if (false == daemonize())
		goto close_fd;

	if (-1 == fcntl(fd, F_SETOWN, getpid()))
		goto close_fd;

	openlog("shusd", LOG_NDELAY | LOG_PID, LOG_USER);

	do {
		/* wait for a signal */
		if (-1 == sigwaitinfo(&mask, &sig))
			goto close_log;

		switch (sig.si_signo) {
			case SIGTERM:
			case SIGINT:
				ret = EXIT_SUCCESS;
				goto close_log;

			default:
				if (rtsig != sig.si_signo)
					goto close_log;
		}

		/*
		 * from now and on, everything we do must be non-blocking, because we
		 * want to handle signals as quick as possible
		 */

		/* the accept() call doesn't block - we know there's a pending client
		 * because we received the asynchronous I/O signal */
		len = sizeof(peer);
		conn = accept(fd, &peer, &len);
		if (-1 == conn)
			break;

		/* enable recv() timeout */
		timeout.tv_sec = RECV_TIMEOUT;
		timeout.tv_usec = 0;
		if (-1 == setsockopt(conn,
		                     SOL_SOCKET,
		                     SO_RCVTIMEO,
		                     (void *) &timeout,
		                     sizeof(timeout)))
			goto disconnect;

		/* enable send() timeout */
		timeout.tv_sec = SEND_TIMEOUT;
		timeout.tv_usec = 0;
		if (-1 == setsockopt(conn,
		                     SOL_SOCKET,
		                     SO_SNDTIMEO,
		                     (void *) &timeout,
		                     sizeof(timeout)))
			goto disconnect;

		/* enable the TCP_CORK flag, to improve efficiency */
		one = 1;
		if (-1 == setsockopt(conn,
		                     IPPROTO_TCP,
		                     TCP_CORK,
		                     (void *) &one,
		                     sizeof(one)))
			goto disconnect;

		/* spawn a child process and respond to the request inside it */
		pid = fork();
		switch (pid) {
			case (-1):
				(void) raise(SIGTERM);
				break;

			case 0:
				handle_conn(sem, conn, &peer, mag, root, user->pw_uid);
		}

disconnect:
		(void) close(conn);
	} while (1);

close_log:
	closelog();

close_fd:
	(void) close(fd);

destroy_sem:
	(void) sem_destroy(sem);

unmap_shm:
	(void) munmap((void *) sem, sizeof(sem_t));

free_shm:
	(void) shm_unlink(SEMAPHORE_NAME);

close_mag:
	magic_close(mag);

free_addrs:
	freeaddrinfo(addrs);

end:
	return ret;
}
