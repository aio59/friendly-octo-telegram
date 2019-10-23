#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define HOST "192.168.254.122"
#define PORT 22
#define USER "a"
#define PASSWORD "cerberus"
#define LISTEN_PORT 29000
#define DESTINATION_PORT 8083
#define LOCALHOST "127.0.0.1"

int local_sock() {
	int sock;
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == -1) {
		exit(-1);
	}

	struct sockaddr_in sin;
	socklen_t sinlen = sizeof(sin);
	char *host = LOCALHOST;
	int port = DESTINATION_PORT;

	sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(host);
    sin.sin_port = htons(port);

    int iretval;
    iretval = connect(sock, (struct sockaddr *)&sin, sinlen);
    if (iretval == -1) {
		fprintf(stderr, "Error connecting socket\n");
    	exit(-1);
    }
	return sock;
}

int forward_connection(ssh_channel channel) {
	int sock;
	sock = local_sock();
	fd_set fds;
	struct timeval tv;
	int rc;
	int buffer[16384];
	int buffer_len;
	int bl, i;

	while (1) {
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		tv.tv_sec = 0;
		tv.tv_usec = 100000;

		rc = select(sock + 1, &fds, NULL, NULL, &tv);
		if (rc == -1) {
			fprintf(stderr, "select\n");
			goto end;
		}
		if (rc && FD_ISSET(sock, &fds)) {
			buffer_len = recv(sock, buffer, sizeof(buffer), 0); // receive buffer from local sock
			if (buffer_len < 0) {
				fprintf(stderr, "Error reading on local sock\n");
				goto end;
			}

			i = 0;
			do {
				bl = ssh_channel_write(channel, buffer, sizeof(buffer)); 
				if (bl < 0) {
					fprintf(stderr, "Error writing on channel\n");
					ssh_channel_free(channel);
					goto end;
				}
				i += bl;
			} while(bl > 0 && i < buffer_len);
		}
		while (1) {
			buffer_len = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
			if (buffer_len < 0) {
				fprintf(stderr, "Error reading on channel\n");
				ssh_channel_free(channel);
				goto end;
			}

			i = 0;
			while (i < buffer_len) {
				bl = send(sock, buffer + i, buffer_len - i, 0);
				if (bl <= 0) {
					fprintf(stderr, "Error writing on sock\n");
					goto end;
				}
				i += bl;
			}
		}
	}

	end:
	close(sock);
	ssh_channel_send_eof(channel);
}

int ssh_tunnel(ssh_session session) {
	int listen_port = LISTEN_PORT;
	int destination_port = DESTINATION_PORT;
	int rc;
	rc = ssh_channel_listen_forward(session, NULL, listen_port, NULL); // wait till request
	if (rc != SSH_OK) {
		fprintf(stderr, "Error opening remote port: %s\n", ssh_get_error(session));
		exit(-1);
	}

	ssh_channel channel;
	channel = ssh_channel_accept_forward(session, 60000, &destination_port);
	if (channel == NULL) {
		fprintf(stderr, "Error waiting for incoming connection: %s\n", ssh_get_error(session));
		exit(-1);
	}
	/*
	int buffer[256];
	int buffer_len;
	buffer_len = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
	if (buffer_len < 0) {
		ssh_channel_send_eof(channel);
		ssh_channel_free(channel);
	}

	fwrite(buffer, 1, buffer_len, stdout);
	*/
	forward_connection(channel);
	ssh_channel_free(channel);
}

int ssh_exec(ssh_session session, char *command) {
	ssh_channel channel;
	channel = ssh_channel_new(session);
	if (channel == NULL) exit(-1);

	int rc;
	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK) {
		ssh_channel_free(channel);
		exit(-1);
	}
	rc = ssh_channel_request_exec(channel, command);
	if (rc != SSH_OK) {
		goto end;
	}

	int buffer[256];
	int buffer_len;
	buffer_len = ssh_channel_read(channel, buffer, sizeof(buffer), 0); // read output
	while (buffer_len > 0) {
		fwrite(buffer, 1, buffer_len, stdout);
		buffer_len = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
	}
	if (buffer_len < 0) {
	}

	end:
	ssh_channel_close(channel);
	ssh_channel_free(channel);
}

int main() {
	ssh_session session;
	session = ssh_new();
	if (session == NULL) exit(-1);

	char *host = HOST;
	int port = PORT;
	char *user = USER;
	char *password = PASSWORD;

	ssh_options_set(session, SSH_OPTIONS_HOST, host);
   	ssh_options_set(session, SSH_OPTIONS_PORT, &port);
   	ssh_options_set(session, SSH_OPTIONS_USER, user);

	int rc;
    rc = ssh_connect(session);
    if (rc != SSH_OK) {
    	printf("Error connecting to localhost: %s\n", ssh_get_error(session));
    	exit(-1);
    }
    rc = ssh_userauth_password(session, NULL, password);
    if (rc != SSH_AUTH_SUCCESS) {
    	printf("Error authenticating with password: %s\n", ssh_get_error(session));
    	exit(-1);
	}

    ssh_tunnel(session);
   	ssh_disconnect(session);
   	ssh_free(session);
}
