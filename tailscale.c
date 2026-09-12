// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

#include "tailscale.h"
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>

// Functions exported by Go.
extern int TsnetNewServer();
extern int TsnetStart(int sd);
extern int TsnetUp(int sd);
extern int TsnetClose(int sd);
extern int TsnetErrmsg(int sd, char* buf, size_t buflen);
extern int TsnetDial(int sd, char* net, char* addr, int* connOut);
extern int TsnetSetDir(int sd, char* str);
extern int TsnetSetStateKey(int sd, char* key);
extern int TsnetSetHostname(int sd, char* str);
extern int TsnetSetAuthKey(int sd, char* str);
extern int TsnetSetControlURL(int sd, char* str);
extern int TsnetSetEphemeral(int sd, int ephemeral);
extern int TsnetSetLogFD(int sd, int fd);
extern int TsnetGetIps(int sd, char *buf, size_t buflen);
extern int TsnetGetRemoteAddr(int listener, int conn, char *buf, size_t buflen);
extern int TsnetListen(int sd, char* net, char* addr, int* listenerOut);
extern int TsnetListenService(int sd, char* name, int port, int terminateTLS, int* listenerOut);
extern int TsnetAccept(int ld, int* connOut);
extern int TsnetLoopback(int sd, char* addrOut, size_t addrLen, char* proxyOut, char* localOut);
extern int TsnetStatusJSON(int sd, char** jsonOut);
extern int TsnetSocks5Listen(int sd, char* addrOut, size_t addrLen, char* credOut);
extern int TsnetWatchIPNBus(int sd, uint64_t mask, int* fdOut);
extern int TsnetLoginInteractive(int sd);
extern int TsnetEditPrefs(int sd, char* maskJSON, char** prefsOut);
extern int TsnetCurrentProfile(int sd, char** jsonOut);
extern int TsnetEnableFunnelToLocalhostPlaintextHttp1(int sd, int localhostPort);

tailscale tailscale_new() {
	return TsnetNewServer();
}

int tailscale_start(tailscale sd) {
	return TsnetStart(sd);
}

int tailscale_up(tailscale sd) {
	return TsnetUp(sd);
}

int tailscale_close(tailscale sd) {
	return TsnetClose(sd);
}

int tailscale_dial(tailscale sd, const char* network, const char* addr, tailscale_conn* conn_out) {
	return TsnetDial(sd, (char*)network, (char*)addr, (int*)conn_out);
}

int tailscale_listen(tailscale sd, const char* network, const char* addr, tailscale_listener* listener_out) {
	return TsnetListen(sd, (char*)network, (char*)addr, (int*)listener_out);
}

int tailscale_listen_service(tailscale sd, const char* name, int port, int terminate_tls, tailscale_listener* listener_out) {
	return TsnetListenService(sd, (char*)name, port, terminate_tls, (int*)listener_out);
}

int tailscale_accept(tailscale_listener ld, tailscale_conn* conn_out) {
	return TsnetAccept(ld, (int*)conn_out);
}

int tailscale_getremoteaddr(tailscale_listener l, tailscale_conn conn, char* buf, size_t buflen) {
	return TsnetGetRemoteAddr(l, conn, buf, buflen);
}

int tailscale_getips(tailscale sd, char* buf, size_t buflen) {
	return TsnetGetIps(sd, buf, buflen);
}

int tailscale_set_dir(tailscale sd, const char* dir) {
	return TsnetSetDir(sd, (char*)dir);
}
int tailscale_set_state_key(tailscale sd, const char* key) {
	return TsnetSetStateKey(sd, (char*)key);
}
int tailscale_set_hostname(tailscale sd, const char* hostname) {
	return TsnetSetHostname(sd, (char*)hostname);
}
int tailscale_set_authkey(tailscale sd, const char* authkey) {
	return TsnetSetAuthKey(sd, (char*)authkey);
}
int tailscale_set_control_url(tailscale sd, const char* control_url) {
	return TsnetSetControlURL(sd, (char*)control_url);
}
int tailscale_set_ephemeral(tailscale sd, int ephemeral) {
	return TsnetSetEphemeral(sd, ephemeral);
}
int tailscale_set_logfd(tailscale sd, int fd) {
	return TsnetSetLogFD(sd, fd);
}

int tailscale_loopback(tailscale sd, char* addr_out, size_t addrlen, char* proxy_cred_out, char* local_api_cred_out) {
	return TsnetLoopback(sd, addr_out, addrlen, proxy_cred_out, local_api_cred_out);
}

int tailscale_status_json(tailscale sd, char** json_out) {
	return TsnetStatusJSON(sd, json_out);
}

int tailscale_socks5_listen(tailscale sd, char* addr_out, size_t addrlen, char* cred_out) {
	return TsnetSocks5Listen(sd, addr_out, addrlen, cred_out);
}

int tailscale_watch_ipn_bus(tailscale sd, uint64_t mask, int* fd_out) {
	return TsnetWatchIPNBus(sd, mask, fd_out);
}

int tailscale_login_interactive(tailscale sd) {
	return TsnetLoginInteractive(sd);
}

int tailscale_edit_prefs(tailscale sd, const char* mask_json, char** prefs_out) {
	return TsnetEditPrefs(sd, (char*)mask_json, prefs_out);
}

int tailscale_current_profile(tailscale sd, char** json_out) {
	return TsnetCurrentProfile(sd, json_out);
}

int tailscale_errmsg(tailscale sd, char* buf, size_t buflen) {
	return TsnetErrmsg(sd, buf, buflen);
}

int tailscale_enable_funnel_to_localhost_plaintext_http1(tailscale sd, int localhostPort) {
	return TsnetEnableFunnelToLocalhostPlaintextHttp1(sd, localhostPort);
}
