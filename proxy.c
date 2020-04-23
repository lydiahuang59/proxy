/*
 * COMP 321 Project 6: Web Proxy
 *
 * This program implements a multithreaded HTTP proxy.
 *
 * Lydia Huang lwh1
 */ 

#include <assert.h>

#include "csapp.h"

static void	client_error(int fd, const char *cause, int err_num, 
		    const char *short_msg, const char *long_msg);
static char    *create_log_entry(const struct sockaddr_in *sockaddr,
		    const char *uri, int size);
static int	parse_uri(const char *uri, char **hostnamep, char **portp,
		    char **pathnamep);


#define NTHREADS 30
FILE *log_file; // log file to write to
pthread_mutex_t lock;
struct thread_help *requests = NULL; // holds all ongoing requests

/* Structure to pass into threads */
struct thread_help {
	int connfd;
	struct sockaddr_in clientaddr;
	int threadnum;
	struct thread_help *next;
};

/* Wrapper of rio_readn that prints errors without exiting */
ssize_t Rio_readn_w(int fd, void *buf, size_t n)
{
	ssize_t s;
	if ((s = rio_readn(fd, buf, n)) < 0) {
		fprintf(stderr, "ERROR: Read failure %s\n", strerror(errno));
		return s;
	}
	return s;
}

/* Wrapper of rio_readlineb that prints errors without exiting */
ssize_t Rio_readlineb_w(rio_t *rp, void *buf, size_t maxlen)
{
	ssize_t s;
	if ((s = rio_readlineb(rp, buf, maxlen)) < 0) {
		fprintf(stderr, "ERROR: Read failure %s\n", strerror(errno));
		return s;
	}
	return s;
}

/* Wrapper of rio_writen that prints errors without exiting */
ssize_t Rio_writen_w(int fd, void *buf, size_t n)
{
	ssize_t s;
	s = rio_writen(fd, buf, n);
	if ((size_t)s != n) {
		fprintf(stderr, "ERROR: Write failure %s\n", strerror(errno));
		return s;
	}
	return s;
}

/* 
 * Requires:
 *   t to be a valid thread_help structure, with a valid sockadd_in that is *
 *   connected to a client and a valid connfd that represents a valid client.
 *
 * Effects:
 *   Reads the HTTP request from the client and sends it to the specified 
 *   server in the request, then receives the response from the server and sends
 *   it back to the client.
 */
void
doit(struct thread_help *t)
{
	char method[MAXLINE], version[MAXLINE], temp[MAXLINE];
	char* buf = malloc(MAXLINE);
	char* hostname;
	char* portp;
	char* pathname;
	int serverfd;
	int n;
	rio_t rio;
	rio_t rio_serv;
	int connfd = t->connfd;
	struct sockaddr_in clientaddr = t->clientaddr;
	int size = MAXLINE;

	/* Read request line */
	rio_readinitb(&rio, connfd);
	bzero(buf, MAXLINE);
	n = Rio_readlineb_w(&rio, buf, MAXLINE);

	/* Request line must at least consist of GET (3) and HTTP/1.x (8) */
	if (n < 11) {
		client_error(connfd, buf, 400, "Bad Request",
		    "Request is malformed");
		Free(t);
		Free(buf);
		Close(connfd);
		return;
	}

	/* If uri is longer than MAXLINE, need to get the rest of it. */
	while (strstr(buf, "\n") == NULL) {
		/* Malloc a new string, then copy old data in */
		char *temp2 = malloc(size + MAXLINE);
		if (!temp2) {
			unix_error("Malloc failed");
		}
		strcat(temp2, buf);
		Rio_readlineb_w(&rio, temp, MAXLINE);
		strcat(temp2, temp);
		Free(buf); // Free old memory.
		buf = temp2; // Then reassign.
		size += MAXLINE; // Increase the size.
		bzero(temp, MAXLINE);
	}
	char uri[size];

	/* Get information out of request line */
	if (sscanf(buf, "%s %s %s", method, uri, version) < 3) {
		client_error(connfd, buf, 400, "Bad Request",
		    "Request is malformed");
		Free(t);
		Free(buf);
		Close(connfd);
		return;
	}
	if (strcasecmp(method, "GET")) {
		client_error(connfd, method, 501, "Not implemented", 
		    "Method is not a GET method");
		Free(t);
		Free(buf);
		Close(connfd);
		return;
	}

	/* Parse URI from GET request */
	if (parse_uri(uri, &hostname, &portp, &pathname) < 0) {
		client_error(connfd, uri, 400, "Bad Request",
		    "Request is malformed");
		Free(t);
		Free(buf);
		Close(connfd);
		return;
	} else {
		/* Open connection to specified server */
		serverfd = open_clientfd((char *) hostname, portp);
		if (serverfd < 0) {
			/* Couldn't access host */
			client_error(connfd, pathname, 403, "Forbidden file",
			    "Server lacks permission to access file");
			Free(t);
			Free(buf);
			Free(hostname);
			Free(portp);
			Free(pathname);
			Close(connfd);
			return;
		}
		rio_readinitb(&rio_serv, serverfd);

		/* send GET request to server */
		if (strcmp(version, "HTTP/1.1") == 0) {
			Rio_writen_w(serverfd, "GET ", strlen("GET "));
			Rio_writen_w(serverfd, pathname, strlen(pathname));
			Rio_writen_w(serverfd, " HTTP/1.1\r\n", 
			    strlen(" HTTP/1.1\r\n"));
			Rio_writen_w(serverfd, "Host: ", strlen("Host: "));
			Rio_writen_w(serverfd, hostname, strlen(hostname));
			Rio_writen_w(serverfd, "\r\nConnection: close\r\n", 
			    strlen("\r\nConnection: close\r\n"));
		} else if (strcmp(version, "HTTP/1.0") == 0) {
			Rio_writen_w(serverfd, buf, strlen(buf));
		} else {
			/* HTTP version is not valid */
			client_error(connfd, version, 505, 
			    "HTTP Version Not Supported",
			    "Client request unsupported protocol version");
			Free(t);
			Free(buf);
			Free(hostname);
			Free(portp);
			Free(pathname);
			Close(connfd);
			return;
		}

		/* Send rest of headers in request */
		bzero(buf, MAXLINE);
		n = Rio_readlineb_w(&rio, buf, MAXLINE);
		while (strcmp(buf, "\r\n") != 0 && n != 0) {
			if (!(strstr(buf, "Connection:") != NULL || 
			    strstr(buf, "Proxy-Connection:") != NULL ||
			    strstr(buf, "Keep-Alive:") != NULL ||
			    strstr(buf, "Host:") != NULL)) {
				Rio_writen_w(serverfd, buf, strlen(buf));
			}
			bzero(buf, MAXLINE);
			n = Rio_readlineb_w(&rio, buf, MAXLINE);
		}
		Rio_writen_w(serverfd, "\r\n", strlen("\r\n"));


		/* Receiver reply from server */
		int response_len = 0;
		bzero(buf, MAXLINE);
		while ((n = Rio_readn_w(serverfd, buf, MAXLINE)) > 0) {
			response_len += n;
			Rio_writen_w(connfd, buf, MAXLINE);
			bzero(buf, MAXLINE);
		}

		/* Create log output */
		char* log_output = create_log_entry(&clientaddr, uri, 
		    response_len);
		fwrite(log_output, 1, strlen(log_output), log_file);
		fflush(log_file);
		fwrite("\n", 1, strlen("\n"), log_file);
		fflush(log_file);

		/* Free all used resources */
		Free(t);
		Free(buf);
		Free(hostname);
		Free(portp);
		Free(pathname);
		Free(log_output);

		Close(serverfd);
		Close(connfd);
	}
	return;
}

/* 
 * Requires:
 *   vargp to be a valid integer.
 *
 * Effects:
 *   Should be performed by every thread concurrently. Every thread checks for 
 *   new requests from the global requests list. A lock is used to prevent data
 *   races. If a thread obtains a lock and a request, it processes it.
 */
void thread(void *vargp)
{
	/* Get the thread number */
	int num = *((int *)vargp);
	Free(vargp);
	Pthread_detach(pthread_self());
	while (1) {
		/* To prevent data races, get the lock first */
		pthread_mutex_lock(&lock);
		/* There is a request, so process it */
		if (requests != NULL) {
			requests->threadnum = num;
			struct thread_help *temp = requests;
			requests = requests->next; // Go to next request
			pthread_mutex_unlock(&lock);
			doit(temp);
		}
		pthread_mutex_unlock(&lock);
	}
	
}

/* 
 * Requires:
 *   argc to be a valid usage of this program.
 *
 * Effects:
 *   Opens a proxy at the specified port, which clients can connect to. All 
 *   requests made to this proxy are processes in parallel using threads. 
 */
int
main(int argc, char **argv)
{

	/* Check the arguments. */
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
		exit(0);
	}

	/* init mutex lock */
	if (pthread_mutex_init(&lock, NULL) != 0) {
		printf("\n mutex init failed\n");
		return 1;
	}

	int listenfd, connfd;
	socklen_t clientlen;
	struct sockaddr_in clientaddr; 
	char client_hostname[MAXLINE], client_port[MAXLINE];
	pthread_t tid;
	int i;

	/* Clear the log file. */
	log_file = fopen("proxy.log", "w");
	log_file = fopen("proxy.log", "a");

	/* Prevent SIGPIPE errors */
	Signal(SIGPIPE, SIG_IGN);

	/* Open the proxy at the specified port */
	listenfd = open_listenfd(argv[1]);
	if (listenfd < 0)
		unix_error("open_listen error");

	/* Create threads for processing proxy requests */
	for (i = 0; i < NTHREADS; i++) {
		int *arg = malloc(sizeof(*arg));
		if (arg == NULL)
			unix_error("Can't allocate memory for thread arg.\n");
		*arg = i;
		Pthread_create(&tid, NULL, (void *)thread, arg);
	}

	while (1) {
		/* Get request information out of client */
		clientlen = sizeof(struct sockaddr_in);
		connfd = Accept(listenfd, (SA *) &clientaddr, &clientlen);
		Getnameinfo((SA *) &clientaddr, clientlen, client_hostname, MAXLINE, client_port, MAXLINE, 0);

		struct thread_help *t = Malloc(sizeof(struct thread_help));
		t->connfd = connfd;
		t->clientaddr = clientaddr;

		/* Add request to request linked list */
		pthread_mutex_lock(&lock);
		t->next = requests;
		requests = t;
		pthread_mutex_unlock(&lock);
	}
	fclose(log_file);
	/* Destroy the locks */
	pthread_mutex_destroy(&lock);

	/* Return success. */
	return (0);
}


/*
 * Requires:
 *   The parameter "uri" must point to a properly NUL-terminated string.
 *
 * Effects:
 *   Given a URI from an HTTP proxy GET request (i.e., a URL), extract the
 *   host name, port, and path name.  Create strings containing the host name,
 *   port, and path name, and return them through the parameters "hostnamep",
 *   "portp", "pathnamep", respectively.  (The caller must free the memory
 *   storing these strings.)  Return -1 if there are any problems and 0
 *   otherwise.
 */
static int
parse_uri(const char *uri, char **hostnamep, char **portp, char **pathnamep)
{
	const char *pathname_begin, *port_begin, *port_end;

	if (strncasecmp(uri, "http://", 7) != 0)
		return (-1);

	/* Extract the host name. */
	const char *host_begin = uri + 7;
	const char *host_end = strpbrk(host_begin, ":/ \r\n");
	if (host_end == NULL)
		host_end = host_begin + strlen(host_begin);
	int len = host_end - host_begin;
	char *hostname = Malloc(len + 1);
	strncpy(hostname, host_begin, len);
	hostname[len] = '\0';
	*hostnamep = hostname;

	/* Look for a port number.  If none is found, use port 80. */
	if (*host_end == ':') {
		port_begin = host_end + 1;
		port_end = strpbrk(port_begin, "/ \r\n");
		if (port_end == NULL)
			port_end = port_begin + strlen(port_begin);
		len = port_end - port_begin;
	} else {
		port_begin = "80";
		port_end = host_end;
		len = 2;
	}
	char *port = Malloc(len + 1);
	strncpy(port, port_begin, len);
	port[len] = '\0';
	*portp = port;

	/* Extract the path. */
	if (*port_end == '/') {
		pathname_begin = port_end;
		const char *pathname_end = strpbrk(pathname_begin, " \r\n");
		if (pathname_end == NULL)
			pathname_end = pathname_begin + strlen(pathname_begin);
		len = pathname_end - pathname_begin;
	} else {
		pathname_begin = "/";
		len = 1;
	}
	char *pathname = Malloc(len + 1);
	strncpy(pathname, pathname_begin, len);
	pathname[len] = '\0';
	*pathnamep = pathname;

	return (0);
}

/*
 * Requires:
 *   The parameter "sockaddr" must point to a valid sockaddr_in structure.  The
 *   parameter "uri" must point to a properly NUL-terminated string.
 *
 * Effects:
 *   Returns a string containing a properly formatted log entry.  This log
 *   entry is based upon the socket address of the requesting client
 *   ("sockaddr"), the URI from the request ("uri"), and the size in bytes of
 *   the response from the server ("size").
 */
static char *
create_log_entry(const struct sockaddr_in *sockaddr, const char *uri, int size)
{
	struct tm result;

	/*
	 * Create a large enough array of characters to store a log entry.
	 * Although the length of the URI can exceed MAXLINE, the combined
	 * lengths of the other fields and separators cannot.
	 */
	const size_t log_maxlen = MAXLINE + strlen(uri);
	char *const log_str = Malloc(log_maxlen + 1);

	/* Get a formatted time string. */
	time_t now = time(NULL);
	int log_strlen = strftime(log_str, MAXLINE, "%a %d %b %Y %H:%M:%S %Z: ",
	    localtime_r(&now, &result));

	/*
	 * Convert the IP address in network byte order to dotted decimal
	 * form.
	 */
	Inet_ntop(AF_INET, &sockaddr->sin_addr, &log_str[log_strlen],
	    INET_ADDRSTRLEN);
	log_strlen += strlen(&log_str[log_strlen]);

	/*
	 * Assert that the time and IP address fields occupy less than half of
	 * the space that is reserved for the non-URI fields.
	 */
	assert(log_strlen < MAXLINE / 2);

	/*
	 * Add the URI and response size onto the end of the log entry.
	 */
	snprintf(&log_str[log_strlen], log_maxlen - log_strlen, " %s %d", uri,
	    size);

	return (log_str);
}

/*
 * Requires:
 *   The parameter "fd" must be an open socket that is connected to the client.
 *   The parameters "cause", "short_msg", and "long_msg" must point to properly 
 *   NUL-terminated strings that describe the reason why the HTTP transaction
 *   failed.  The string "short_msg" may not exceed 32 characters in length,
 *   and the string "long_msg" may not exceed 80 characters in length.
 *
 * Effects:
 *   Constructs an HTML page describing the reason why the HTTP transaction
 *   failed, and writes an HTTP/1.0 response containing that page as the
 *   content.  The cause appearing in the HTML page is truncated if the
 *   string "cause" exceeds 2048 characters in length.
 */
static void
client_error(int fd, const char *cause, int err_num, const char *short_msg,
    const char *long_msg)
{
	char body[MAXBUF], headers[MAXBUF], truncated_cause[2049];

	assert(strlen(short_msg) <= 32);
	assert(strlen(long_msg) <= 80);
	/* Ensure that "body" is much larger than "truncated_cause". */
	assert(sizeof(truncated_cause) < MAXBUF / 2);

	/*
	 * Create a truncated "cause" string so that the response body will not
	 * exceed MAXBUF.
	 */
	strncpy(truncated_cause, cause, sizeof(truncated_cause) - 1);
	truncated_cause[sizeof(truncated_cause) - 1] = '\0';

	/* Build the HTTP response body. */
	snprintf(body, MAXBUF,
	    "<html><title>Proxy Error</title><body bgcolor=""ffffff"">\r\n"
	    "%d: %s\r\n"
	    "<p>%s: %s\r\n"
	    "<hr><em>The COMP 321 Web proxy</em>\r\n",
	    err_num, short_msg, long_msg, truncated_cause);

	/* Build the HTTP response headers. */
	snprintf(headers, MAXBUF,
	    "HTTP/1.0 %d %s\r\n"
	    "Content-type: text/html\r\n"
	    "Content-length: %d\r\n"
	    "\r\n",
	    err_num, short_msg, (int)strlen(body));

	/* Write the HTTP response. */
	if (rio_writen(fd, headers, strlen(headers)) != -1)
		rio_writen(fd, body, strlen(body));
}

// Prevent "unused function" and "unused variable" warnings.
static const void *dummy_ref[] = { client_error, create_log_entry, dummy_ref,
    parse_uri };
