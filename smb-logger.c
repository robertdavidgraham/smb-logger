/******************************************************************************
	SMB LOGGER

	A quick and dirty honetpot to catch incoming connections to
	Microsoft NetBIOS/SMB, such as the WannaCry botnet


	Tips for reading the code:
		- it runs on Windows, Linux, and Mac OS
		- it's IPv6 and IPv4 enabled

******************************************************************************/
#define _CRT_SECURE_NO_WARNINGS 1
#if defined(WIN32)
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <intrin.h>
#include <process.h>
#define sleep(secs) Sleep(1000*(secs))
#define WSA(err) (WSA##err)
typedef CRITICAL_SECTION pthread_mutex_t;
#define pthread_mutex_lock(p) EnterCriticalSection(p)
#define pthread_mutex_unlock(p) LeaveCriticalSection(p)
#define pthread_mutex_init(p,q) InitializeCriticalSection(p)
#define pthread_create(handle,x,pfn,data) (*(handle)) = _beginthread(pfn,0,data)
typedef uintptr_t pthread_t;
#define snprintf _snprintf
#else
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <pthread.h>
#define WSAGetLastError() (errno)
#define closesocket(fd) close(fd)
#define WSA(err) (err)
#endif
#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32")
#endif

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

/******************************************************************************
 * A mutex so multiple threads printing output don't conflict with
 * each other
 ******************************************************************************/
pthread_mutex_t output;


/******************************************************************************
 * Arguments pass to each thread. Creating a thread only allows passing in
 * a single pointer, so we have to put everything we want passed to the
 * thread in a structure like this.
 ******************************************************************************/
struct ThreadArgs {
	pthread_t handle;
	int fd;
	FILE *fp_passwords;
	FILE *fp_ips;
	FILE *fp_csv;
	struct sockaddr_in6 peer;
	socklen_t peerlen;
	char peername[256];
};


/******************************************************************************
 * Translate sockets error codes to helpful text for printing
 ******************************************************************************/
static const char *
error_msg(unsigned err)
{
	static char buf[256];
	switch (err) {
	case WSA(ECONNRESET): return "TCP connection reset";
	case WSA(ECONNREFUSED): return "Connection refused";
	case WSA(ETIMEDOUT): return "Timed out";
	case WSA(ECONNABORTED): return "Connection aborted";
	case WSA(EACCES): return "Access denied";
	case WSA(EADDRINUSE): return "Port already in use";
	case 11: return "Timed out";
	case 0: return "TCP connection closed";
	default:   
		snprintf(buf, sizeof(buf), "err#%u", err);
		return buf;
	}
}

/******************************************************************************
 * Print to stderr. Right now, it's just a wrapper aroun fprintf(stderr), but
 * I do it this way so I can later add different DEBUG levels.
 ******************************************************************************/
int ERROR_MSG(const char *fmt, ...)
{
	va_list marker;
	va_start(marker, fmt);
	vfprintf(stderr, fmt, marker);
	va_end(marker);
	return -1;
}

/******************************************************************************
 * On modern systems (Win7+, macOS, Linux, etc.), an "anyipv6" socket always
 * is backwards compatible with IPv4. So we create an IPv6 socket to handle
 * both versions simultaneously. This will inevitably fail on some system,
 * so eventually I'll have to write an IPv4 version of this function.
 ******************************************************************************/
int
create_ipv6_socket(int port)
{
	int fd;
	int err;
	struct sockaddr_in6 localaddr;

	/* Create a generic socket. IPv6 includes IPv4 */
	fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (fd <= 0) {
		ERROR_MSG("socket(AF_INET6): could not create socket: %s\n",
			error_msg(WSAGetLastError()));
		return -1;
	}

	/* Make it a dual stack IPv4/IPv6 socket. This step is unnecessary on
	 * some operating systems/versions, but necessary on some others */
	{
		int no = 0;
		err = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&no, sizeof(no));
		if (err != 0) {
			ERROR_MSG("setsockopt(!IPV6_V6ONLY): %s\n",
				error_msg(WSAGetLastError()));
			closesocket(fd);
			return -1;
		}
	}

#ifndef WIN32
	/* Reuse address */
	{
		int yes = 1;
		err = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
		if (err != 0) {
			ERROR_MSG("setsockopt(SO_REUSEADDR): %s\n",
				error_msg(WSAGetLastError()));
			closesocket(fd);
			return -1;
		}
	}
#endif

	/* Bind to local port. Again note that while I"m binding for IPv6, it's
	 * also setting up a service for IPv4. */
	memset(&localaddr, 0, sizeof(localaddr));
	localaddr.sin6_family = AF_INET6;
	localaddr.sin6_port = htons(port);
	localaddr.sin6_addr = in6addr_any;
	err = bind(fd, (struct sockaddr*)&localaddr, sizeof(localaddr));
	if (err < 0) {
		ERROR_MSG("bind(%u): %s\n", port,
			error_msg(WSAGetLastError()));
		closesocket(fd);
		return -1;
	}

	/* Now the final initializaiton step */
	err = listen(fd, 10);
	if (err < 0) {
		ERROR_MSG("listen(%u): %s\n", port,
			error_msg(WSAGetLastError()));
		closesocket(fd);
		return -1;
	}

	return fd;
}


/******************************************************************************
 * Blacklist some bad characters to avoid the most obvious attempts of 
 * entering bad passwords designed to hack the system (shell injection,
 * HTML injection, SQL injection).
 ******************************************************************************/
void 
print_string(FILE *fp, const char *str, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		char c = str[i];
		if (!isprint(c & 0xFF) || c == '\\' || c == '<' || c == '\'' || c == ' ' || c == '\"' || c == ',')
			fprintf(fp, "\\x%02x", c & 0xFF);
		else
			fprintf(fp, "%c", c);
	}
}

/******************************************************************************
 * Compares two strings, one nul-terminated, the other length encoded
 ******************************************************************************/
int
matches(const char *rhs, const char *lhs, int len)
{
	if (strlen(rhs) == len && memcmp(rhs, lhs, len) == 0)
		return 1;
	else
		return 0;
}

/******************************************************************************
* Print the results.
******************************************************************************/
void
print_passwords(FILE *fp, const char *login, int login_len, const char *password, int password_len)
{
	if (fp == NULL)
		return;

	if (matches("shell", login, login_len) && matches("sh", password, password_len))
		return;
	if (matches("enable", login, login_len) && matches("system", password, password_len))
		return;

	/* pretty print the two fields */
	pthread_mutex_lock(&output);
	print_string(fp, login, login_len);
	fprintf(fp, " ");
	print_string(fp, password, password_len);
	fprintf(fp, "\n");
	fflush(fp);
	pthread_mutex_unlock(&output);
}

/******************************************************************************
 * Print which machines are connecting
 ******************************************************************************/
void
print_ip(FILE *fp, const char *hostname)
{
	if (fp == NULL)
		return;

	pthread_mutex_lock(&output);
	fprintf(fp, "%s\n", hostname);
	fflush(fp);
	pthread_mutex_unlock(&output);
}


/******************************************************************************
 * Create a CSV formatted line with all the information on one line.
 ******************************************************************************/
void
print_csv(FILE *fp, time_t now, const char *hostname,
	const char *login, int login_len,
	const char *password, int password_len)
{
	struct tm *tm;
	char str[128];

	if (fp == NULL)
		return;

	tm = gmtime(&now);
	if (tm == NULL) {
		perror("gmtime");
		return;
	}

	strftime(str, sizeof(str), "%Y-%m-%d %H:%M:%S", tm);

	pthread_mutex_lock(&output);

	/* time-integer, time-formatted, username, password*/
	fprintf(fp, "%u,%s,%s,",
		(unsigned)now,
		str,
		hostname);
	print_string(fp, login, login_len);
	fprintf(fp, ",");
	print_string(fp, password, password_len);
	fprintf(fp, "\n");

	fflush(fp);
	pthread_mutex_unlock(&output);
}


/******************************************************************************
 * Receive a NetBIOS datagram from across the TCP connection
 ******************************************************************************/
int
recv_netbios(int fd, unsigned char *buf, int sizeof_buf, int flags, int *type)
{
	int done = 0;
	unsigned char c;
	int len;
	int netbios_len;
	int i;
	int offset = 0;

	/* receive the type field */
	len = recv(fd, (char*)&c, 1, flags);
	if (len <= 0) {
		ERROR_MSG("recv(1): %s\n",
				error_msg(WSAGetLastError()));
		return -1;
	}
	*type = c;

	/* reeive the length field */
	netbios_len = 0;
	for (i=0; i<3; i++) {
		len = recv(fd, (char*)&c, 1, flags);
		if (len <= 0)
			return -1;
		netbios_len <<= 8;
		netbios_len |= c;
	}
	if ((netbios_len >> 17) != 0) {
		fprintf(stderr, "bad netbios length: should never happen\n");
		return -1;
	}
	if (netbios_len > sizeof_buf) {
		fprintf(stderr, "netbios buffer overflow\n");
		return -1;
	}

	/* Now receive the NetBIOS payload */
	while (offset < netbios_len) {
		len = recv(fd, buf+offset, netbios_len - offset, flags);
		if (len <= 0)
			return -1;
		offset += len;
	}

	return netbios_len;
}

/******************************************************************************
 ******************************************************************************/
void handle_smbv2_request(const unsigned char *buf, size_t buf_size, const char *peername)
{
}

/******************************************************************************
 ******************************************************************************/
void handle_smb_request(const unsigned char *buf, size_t buf_size, const char *peername)
{
	size_t offset = 0;

	struct SMBv1_header {
		unsigned command;
		unsigned flags;
		unsigned flags2;
		unsigned char security_features[8];
		unsigned pid;
		unsigned tid;
		unsigned uid;
		unsigned mid;

		unsigned word_count;
		unsigned byte_count;
	} smb;

	/* ProtocolID
	 * \xff SMB - SMBv1
	 * \xfe SMB - SMBv2 or SMBv3
	 */
	if (offset + 4 >= buf_size) {
		fprintf(stderr, "%s: truncated packet\n", peername);
		return;
	}
	if (memcmp(buf, "\xFE" "SMB", 4) == 0)
		handle_smbv2_request(buf, buf_size, peername);
	if (memcmp(buf, "\xFF" "SMB", 4) != 0) {
		fprintf(stderr, "%s: unknown SMB version\n", peername);
		return;
	}

	if (buf_size < 32) {
		fprintf(stderr, "%s: SMBv1 truncated, length=%u\n", peername, (unsigned)buf_size);
		return;
	}

	smb.command = buf[4];
	smb.status = buf[5] | buf[6]<<8 | buf[7]<<16 | buf[8]<<24;
	smb.flags = buf[9];
	smb.flags2 = buf[10] | buf[11]<<8;
	smb.pid = buf[12]<<16 | buf[13]<<24;
	memcpy(smb.security_features, buf+14, 8);
	smb.tid = buf[24] | buf[25]<<8;
	smb.pid |= buf[26] | buf[27]<<8;
	smb.uid = buf[28] | buf[29]<<8;
	smb.mid = buf[30] | buf[31]<<8;

	if (buf_size >= 32 + 3) {
		smb.word_count = buf[32];
		smb.byte_count = buf[33] | buf[34]<<8;
		offset = 35;
	} else {
		smb.word_count = 0;
		smb.byte_count = 0;
		offset = 32;
	}

	switch (smb.command) {
	case 0x72: /* Negotiate protocol */
		handle_negotiate_protocol(&smb, buf, offset, buf_size, peername);
		break;
	default:
		fprintf(stderr, "%s: command=0x%02x len=%u\n", peername, smb.command, buf_size-offset);
	}

}


/******************************************************************************
 ******************************************************************************/
void
str_append(char *str, size_t *offset, size_t sizeof_str, char c)
{
	if (*offset + 1 < sizeof_str) {
		str[(*offset)++] = c;
		str[(*offset)] = '\0';
	}
}

void
str_append_str(char *str, size_t *offset, size_t sizeof_str, const char *rhs, size_t rhs_len)
{
	size_t i;

	for (i=0; i<rhs_len; i++)
		str_append(str, offset, sizeof_str, rhs[i]);
}

/******************************************************************************
 ******************************************************************************/
void handle_session_request(const unsigned char *buf, size_t buf_size, const char *peername)
{
	size_t offset = 0;
	char str[256];
	size_t str_offset;
	struct tm *tm;
	time_t now = time(0);

	/* format the time */
	tm = gmtime(&now);
	if (tm == NULL) {
		perror("gmtime");
		return;
	}
	strftime(str, sizeof(str), "%Y-%m-%d %H:%M:%S ", tm);
	str_offset = strlen(str);

	/* append peername */
	str_append_str(str, &str_offset, sizeof(str), peername, strlen(peername));


	/* Called name prefix */
	str_append_str(str, &str_offset, sizeof(str), " called=\"", strlen(" called=\""));
	if (offset < buf_size) {
		size_t name_len = buf[offset++];
		unsigned letter = 0;

		while (offset + 1 < buf_size && name_len >= 2) {
			unsigned char c;

			c = buf[offset++];
			if (c < 'A' || ('A' + 16) < c)
				c = 'A';
			letter = (c - 'A');
			
			c = buf[offset++];
			if (c < 'A' || ('A' + 16) < c)
				c = 'A';
			letter <<= 4;
			letter |= (c - 'A');

			if (isalnum(letter) || ispunct(letter)) {
				str_append(str, &str_offset, sizeof(str), letter);
			} else if (letter == ' ' && name_len > 2) {
				str_append(str, &str_offset, sizeof(str), letter);
			} else {
				str_append(str, &str_offset, sizeof(str), '<');
				str_append(str, &str_offset, sizeof(str), "01234567890ABCDEF"[letter>>4]);
				str_append(str, &str_offset, sizeof(str), "01234567890ABCDEF"[letter&0xF]);
				str_append(str, &str_offset, sizeof(str), '>');
			}
			name_len -= 2;
		}
	}

	/* Called name suffix */
	while (offset < buf_size) {
		size_t name_len = buf[offset++];
		unsigned letter = 0;

		if (name_len == 0)
			break;

		str_append(str, &str_offset, sizeof(str), '.');

		while (offset + 1 < buf_size && name_len >= 1) {
			unsigned char letter;

			letter = buf[offset++];

			if (isalnum(letter) || ispunct(letter)) {
				str_append(str, &str_offset, sizeof(str), letter);
			} else {
				str_append(str, &str_offset, sizeof(str), '<');
				str_append(str, &str_offset, sizeof(str), "01234567890ABCDEF"[letter>>4]);
				str_append(str, &str_offset, sizeof(str), "01234567890ABCDEF"[letter&0xF]);
				str_append(str, &str_offset, sizeof(str), '>');
			}
			name_len += 1;
		}
	}

	/* caller */
	str_append_str(str, &str_offset, sizeof(str), "\" caller=\"", strlen("\" caller=\""));
	if (offset < buf_size) {
		size_t name_len = buf[offset++];
		unsigned letter = 0;

		while (offset + 1 < buf_size && name_len >= 2) {
			unsigned char c;

			c = buf[offset++];
			if (c < 'A' || ('A' + 16) < c)
				c = 'A';
			letter = (c - 'A');
			
			c = buf[offset++];
			if (c < 'A' || ('A' + 16) < c)
				c = 'A';
			letter <<= 4;
			letter |= (c - 'A');

			if (isalnum(letter) || ispunct(letter)) {
				str_append(str, &str_offset, sizeof(str), letter);
			} else if (letter == ' ' && name_len > 2) {
				str_append(str, &str_offset, sizeof(str), letter);
			} else {
				str_append(str, &str_offset, sizeof(str), '<');
				str_append(str, &str_offset, sizeof(str), "01234567890ABCDEF"[letter>>4]);
				str_append(str, &str_offset, sizeof(str), "01234567890ABCDEF"[letter&0xF]);
				str_append(str, &str_offset, sizeof(str), '>');
			}
			name_len -= 2;
		}
	}

	/* Called name suffix */
	while (offset < buf_size) {
		size_t name_len = buf[offset++];
		unsigned letter = 0;

		if (name_len == 0)
			break;

		str_append(str, &str_offset, sizeof(str), '.');

		while (offset + 1 < buf_size && name_len >= 1) {
			unsigned char letter;

			letter = buf[offset++];

			if (isalnum(letter) || ispunct(letter)) {
				str_append(str, &str_offset, sizeof(str), letter);
			} else {
				str_append(str, &str_offset, sizeof(str), '<');
				str_append(str, &str_offset, sizeof(str), "01234567890ABCDEF"[letter>>4]);
				str_append(str, &str_offset, sizeof(str), "01234567890ABCDEF"[letter&0xF]);
				str_append(str, &str_offset, sizeof(str), '>');
			}
			name_len += 1;
		}
	}
	str_append_str(str, &str_offset, sizeof(str), "\" ", strlen("\" "));

	printf("%s\n", str);
}

/******************************************************************************
 * This is a thread created whenever a connection is accepted, which is then
 * responsible for handling the connection with blocking calls, and eventually
 * cleanup when the connection ends. We set a recv timeout so that the 
 * connection won't stay alive indefinitely.
 ******************************************************************************/
void *handle_connection(void *v_args)
{
	struct ThreadArgs *args = (struct ThreadArgs *)v_args;
	int fd = args->fd;
	int netbios_length;
	int netbios_type;
	int flags = 0;
	const size_t buf_size = 128 * 1024 * 1024;
	unsigned char *buf;
	
	buf = malloc(buf_size);
	if (buf == 0) {
		fprintf(stderr, "out of memory, exiting\n");
		exit(1);
	}

#ifdef MSG_NOSIGNAL
	flags |= MSG_NOSIGNAL;
#endif


	/* Set receive timeout of 1 minute. Windows can go suck an egg by deciding
	 * to be different here. */
#ifdef WIN32
	{
		DWORD tv;
		int err;

		tv = 60000;

		err = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
		if (err) {
			ERROR_MSG("setsockopt(SO_RECVTIMEO): %s\n",
				error_msg(WSAGetLastError()));
		}
	}
#else
	{
		struct timeval tv;
		int err;

		tv.tv_sec = 60;
		tv.tv_usec = 0;

		err = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
		if (err) {
			ERROR_MSG("setsockopt(SO_RECVTIMEO): %s\n",
				error_msg(WSAGetLastError()));
		}
	}
#endif


again:

	/* Get NetBIOS packet */
	netbios_type = 0;
	netbios_length = recv_netbios(fd, buf, buf_size, flags, &netbios_type);
	if (netbios_length <= 0)
		goto error;

	/* do different processing depending on type */
	switch (netbios_type) {
	case 0x00: /* message */
		handle_smb_request(buf, buf_size, args->peername);
		break;
	case 0x81: /* session request */
		handle_session_request(buf, buf_size, args->peername);
		send(fd, "\x82\x00\x00\x00", 4, flags);
		break;
	case 0x85:
	default:
		break;
	}

	goto again;


end:
	closesocket(fd);
	ERROR_MSG("[-] %s: close()\n", args->peername);
	free(args);
	free(buf);
	return NULL;
error:
	ERROR_MSG("[-] %s: recv(): %s\n", args->peername,
		error_msg(WSAGetLastError()));
	goto end;
}


/******************************************************************************
 ******************************************************************************/
void
daemon_thread(int port, FILE *fp_passwords, FILE *fp_ips, FILE *fp_csv)
{

	int fd;
	
	fd = create_ipv6_socket(port);
	if (fd <= 0)
		return;

	for (;;) {
		int newfd;
		struct ThreadArgs *args;

		/* accept a new connection */
		newfd = accept(fd, 0, 0);
		if (newfd <= 0) {
			ERROR_MSG("accept(%u): %s\n", port,
				error_msg(WSAGetLastError()));
			break;
		}

		/* Create new structure to hold per-thread-dat */
		args = malloc(sizeof(*args));
		memset(args, 0, sizeof(*args));
		args->fd = newfd;
		args->fp_passwords = fp_passwords;
		args->fp_ips = fp_ips;
		args->fp_csv = fp_csv;
		args->peerlen = sizeof(args->peer);
		getpeername(args->fd, (struct sockaddr*)&args->peer, &args->peerlen);
		getnameinfo((struct sockaddr*)&args->peer, args->peerlen, args->peername, sizeof(args->peername), NULL, 0, NI_NUMERICHOST| NI_NUMERICSERV);
		if (memcmp(args->peername, "::ffff:", 7) == 0)
			memmove(args->peername, args->peername + 7, strlen(args->peername + 7) + 1);
		fprintf(stderr, "[+] %s: connect\n", args->peername);

		pthread_create(&args->handle, 0, handle_connection, args);

#ifndef WIN32
		/* clean up the thread handle, otherwise we have a small memory
		 * leak of handles. Thanks to Stefan Laudemann for pointing
		 * this out. I suspect it's more than just 8 bytes for the handle,
		 * but that there are kernel resources that we'll run out of
		 * too. */
		pthread_detach(args->handle);
#endif
	}

	closesocket(fd);
}

/******************************************************************************
******************************************************************************/
FILE *
open_output(int *in_i, char *argv[], int argc)
{
	int i = *in_i;
	const char *filename = NULL;

	/* Allow either with/without space:
	 *	-cfilename.txt
	 * or
	 *	-c filename.txt 
	 */
	if (argv[i][2] == '\0') {
		i = ++(*in_i);
		if (i >= argc) {
			fprintf(stderr, "expected parameter after -%c\n", argv[i][1]);
			exit(1);
		}
		filename = argv[i];
	}
	else
		filename = argv[i] + 2;

	/* If the filename is a dash, then redirect to console output*/
	if (strcmp(filename, "-") == 0)
		return stdout;

	/* If the filename is "NULL", then don't output anything */
	else if (strcmp(filename, "null") == 0)
		return NULL;

	/* Create a file to output to*/
	else {
		FILE *fp;
		fp = fopen(filename, "wt");
		if (fp == NULL) {
			perror(filename);
			exit(1);
			return NULL;
		}
		else
			return fp;
	}
}

/******************************************************************************
 ******************************************************************************/
int
main(int argc, char *argv[])
{
	FILE *fp_passwords = stdout;
	FILE *fp_ips = stdout;
	FILE *fp_csv = NULL;
	int i;
	int port = 23;

	/*
	* One-time program startup stuff for legacy Windows.
	*/
#if defined(WIN32)
	{WSADATA x; WSAStartup(0x101, &x);}
#endif

	pthread_mutex_init(&output, 0);

	fprintf(stderr, "\n--- smb-logger/0.1 ---\n");
	fprintf(stderr, "https://github.com/robertdavidgraham/smb-logger\n");

	/* Read configuration parameters */
	for (i = 1; i < argc; i++) {
		if (argv[i][0] != '-') {
			fprintf(stderr, "unknown parameter: %s\n", argv[i]);
			exit(1);
		}
		switch (argv[i][1]) {
		case 'p': /* port number to listen on */
		{
			char *arg;
			if (isdigit(argv[i][2])) {
				arg = &argv[i][2];
			} else {
				if (++i >= argc) {
					fprintf(stderr, "expected parameter after -%c\n", 'i');
					exit(1);
				}
				arg = argv[i];
			}
			if (strtoul(arg, 0, 0) < 1 || strtoul(arg, 0, 0) > 65535) {
				fprintf(stderr, "expected port number between 1..65535\n");
				exit(1);
			}
			port = strtoul(arg, 0, 0);
		}
			break;
		case 'h':
		case '?':
		case 'H':
			fprintf(stderr, "usage:\n smb-logger [-p listen-port]\n");
			exit(1);
			break;
		}
	}

	daemon_thread(port, fp_passwords, fp_ips, fp_csv);

	return 0;
}

