/* nikonptpip.c
 *
 * Copyright (C) 2024 MEO (for Gemini)
 * Copyright (C) 2006-2022 Marcus Meissner <marcus@jet.franken.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA
 */
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "ptpip-private.h"
#include "nikonptpip-private.h"

#ifdef WIN32
# include <winsock2.h>
# include <ws2tcpip.h>
#else
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <fcntl.h>
#endif

#include <gphoto2/gphoto2-library.h>
#include <gphoto2/gphoto2-port-log.h>

#include "libgphoto2/i18n.h"

#include "ptp.h"
#include "ptp-private.h"

#define ptpip_len		0
#define ptpip_type		4
#define ptpip_initcmd_guid	8
#define ptpip_initcmd_name	24
#define ptpip_eventinit_idx	8
#define ptpip_eventinit_size	12
#define ptpip_cmdack_idx	0
#define ptpip_cmdack_guid	4
#define ptpip_cmdack_name	20


static uint16_t
nikonptpip_init_command_request (PTPParams* params)
{
	char		hostname[100];
	unsigned char*	cmdrequest;
	unsigned int	i;
	int 		len, ret;
	unsigned char	guid[16];

	ptp_nikon_getptpipguid(guid);
#if !defined (WIN32)
	if (gethostname (hostname, sizeof(hostname)))
		return PTP_RC_GeneralError;
#else
	DWORD hostname_size = (DWORD)sizeof(hostname);
	if (!GetComputerNameA(hostname, &hostname_size))
		return PTP_RC_GeneralError;
#endif
	len = ptpip_initcmd_name + (strlen(hostname)+1)*2 + 4;

	cmdrequest = malloc(len);
	htod32a(&cmdrequest[ptpip_type],PTPIP_INIT_COMMAND_REQUEST);
	htod32a(&cmdrequest[ptpip_len],len);

	memcpy(&cmdrequest[ptpip_initcmd_guid], guid, 16);
	for (i=0;i<strlen(hostname)+1;i++) {
		cmdrequest[ptpip_initcmd_name+i*2] = hostname[i];
		cmdrequest[ptpip_initcmd_name+i*2+1] = 0;
	}
	htod16a(&cmdrequest[ptpip_initcmd_name+(strlen(hostname)+1)*2], 0x0000);
	htod16a(&cmdrequest[ptpip_initcmd_name+(strlen(hostname)+1)*2+2], 0x0001);

	GP_LOG_DATA ((char*)cmdrequest, len, "ptpip/init_cmd data:");
	ret = ptpip_write_with_timeout (params->cmdfd, cmdrequest, len, PTPIP_DEFAULT_TIMEOUT_S, PTPIP_DEFAULT_TIMEOUT_MS);
	free (cmdrequest);
	if (ret == PTPSOCK_ERR) {
		ptpip_perror("write init cmd request");
		if (ptpip_get_socket_error() == ETIMEDOUT)
			return PTP_ERROR_TIMEOUT;
		return PTP_ERROR_IO;
	}
	if (ret != len) return PTP_RC_GeneralError;
	return PTP_RC_OK;
}

static uint16_t
nikonptpip_init_command_ack (PTPParams* params)
{
	PTPIPHeader	hdr;
	unsigned char	*data = NULL;
	uint16_t 	ret;
	int		i;
	unsigned short	*name;

	ret = ptp_ptpip_generic_read (params, params->cmdfd, &hdr, &data);
	if (ret != PTP_RC_OK) return ret;
	if (hdr.type != dtoh32(PTPIP_INIT_COMMAND_ACK)) {
		free (data);
		if (hdr.type == PTPIP_INIT_FAIL)
			return PTP_RC_AccessDenied;
		return PTP_RC_GeneralError;
	}
	params->eventpipeid = dtoh32a(&data[ptpip_cmdack_idx]);
	memcpy (params->cameraguid, &data[ptpip_cmdack_guid], 16);
	name = (unsigned short*)&data[ptpip_cmdack_name];
	for (i=0;name[i];i++) ;
	params->cameraname = calloc((i+1),sizeof(uint16_t));
	for (i=0;name[i];i++)
		params->cameraname[i] = name[i];
	free (data);
	return PTP_RC_OK;
}

static uint16_t
nikonptpip_init_event_request (PTPParams* params)
{
	unsigned char	evtrequest[ptpip_eventinit_size];
	int 		ret;

	htod32a(&evtrequest[ptpip_type],PTPIP_INIT_EVENT_REQUEST);
	htod32a(&evtrequest[ptpip_len],ptpip_eventinit_size);
	htod32a(&evtrequest[ptpip_eventinit_idx],params->eventpipeid);

	ret = ptpip_write_with_timeout (params->evtfd, evtrequest, ptpip_eventinit_size, PTPIP_DEFAULT_TIMEOUT_S, PTPIP_DEFAULT_TIMEOUT_MS);
	if (ret == PTPSOCK_ERR) {
		ptpip_perror("write init evt request");
		if (ptpip_get_socket_error() == ETIMEDOUT) return PTP_ERROR_TIMEOUT;
		return PTP_ERROR_IO;
	}
	if (ret != ptpip_eventinit_size) return PTP_RC_GeneralError;
	return PTP_RC_OK;
}

static uint16_t
nikonptpip_init_event_ack (PTPParams* params)
{
	PTPIPHeader	hdr;
	unsigned char	*data = NULL;
	uint16_t	ret;

	ret = ptp_ptpip_evt_read (params, &hdr, &data);
	if (ret != PTP_RC_OK) return ret;
	free (data);
	if (hdr.type != dtoh32(PTPIP_INIT_EVENT_ACK)) return PTP_RC_GeneralError;
	return PTP_RC_OK;
}

static uint16_t
nikonptpip_sta_phase1_auth (PTPParams *params)
{
	uint16_t ret;
	PTPContainer ptp;

	ret = ptp_opensession(params, 1);
	if (ret != PTP_RC_OK) {
		ptp_error(params, "Nikon STA: OpenSession failed with 0x%04x", ret);
		return ret;
	}

	ptp_debug(params, "Nikon STA: Sending command 0x952b.");
	memset(&ptp, 0, sizeof(ptp));
	ptp.Code = 0x952b;
	ptp.Nparam = 0;
	ret = ptp_transaction_new(params, &ptp, PTP_DP_GETDATA, 0, NULL);
	if (ret != PTP_RC_OK) {
		ptp_error(params, "Nikon STA: Command 0x952b failed with 0x%04x", ret);
		return ret;
	}

	ptp_debug(params, "Nikon STA: Sending command 0x935a.");
	memset(&ptp, 0, sizeof(ptp));
	ptp.Code = 0x935a;
	ptp.Nparam = 1;
	ptp.Param1 = 0x2001; 
	ret = ptp_transaction_new(params, &ptp, PTP_DP_GETDATA, 0, NULL);
	if (ret != PTP_RC_OK) {
		ptp_error(params, "Nikon STA: Command 0x935a failed with 0x%04x", ret);
		return ret;
	}
	ptp_debug(params, "Nikon STA: Phase 1 authentication successful.");

	ptp_closesession(params);
	return PTP_RC_OK;
}

int
ptp_nikonptpip_connect (PTPParams* params, const char *address) {
	char 		*addr, *s;
	int		port;
	struct sockaddr_in	saddr;
	uint16_t	ret;

	if (NULL == strchr (address,':')) return GP_ERROR_BAD_PARAMETERS;

	addr = strdup (address);
	if (!addr) return GP_ERROR_NO_MEMORY;
	s = strchr (addr,':');
	*s = '\0';
	port = 15740;
	if (sscanf (s+1,"%d",&port) != 1) {
		free (addr);
		return GP_ERROR_BAD_PARAMETERS;
	}

#ifdef HAVE_INET_ATON
	if (!inet_aton (addr,  &saddr.sin_addr)) {
#else
	if (inet_pton(AF_INET, addr, &saddr.sin_addr) != 1) {
#endif
		free (addr);
		return GP_ERROR_BAD_PARAMETERS;
	}
	saddr.sin_port		= htons(port);
	saddr.sin_family	= AF_INET;
	free (addr);

	GP_LOG_D ("Nikon STA: Phase 1 connect.");
	params->cmdfd = socket (PF_INET, SOCK_STREAM, 0);
	if (params->cmdfd == PTPSOCK_INVALID) return GP_ERROR_IO;
	if (ptpip_set_nonblock(params->cmdfd) == -1) {
		PTPSOCK_CLOSE (params->cmdfd);
		return GP_ERROR_IO;
	}
	if (ptpip_connect_with_timeout (params->cmdfd, (struct sockaddr*)&saddr, sizeof(saddr), 5, 0) == -1) {
		PTPSOCK_CLOSE (params->cmdfd);
		return GP_ERROR_IO;
	}

	ret = nikonptpip_init_command_request (params);
	if (ret != PTP_RC_OK) { PTPSOCK_CLOSE(params->cmdfd); return translate_ptp_result(ret); }
	ret = nikonptpip_init_command_ack (params);
	if (ret != PTP_RC_OK) { PTPSOCK_CLOSE(params->cmdfd); return translate_ptp_result(ret); }

	ret = nikonptpip_sta_phase1_auth(params);
	if (ret != PTP_RC_OK) {
		ptp_ptpip_disconnect(params);
		return translate_ptp_result(ret);
	}
	
	GP_LOG_D ("Nikon STA: Phase 1 done, disconnecting for Phase 2.");
	ptp_ptpip_disconnect(params);
#ifdef WIN32
    Sleep(5000);
#else
    sleep(5);
#endif

	GP_LOG_D ("Nikon STA: Phase 2 reconnect.");
	params->cmdfd = socket (PF_INET, SOCK_STREAM, 0);
	if (params->cmdfd == PTPSOCK_INVALID) return GP_ERROR_IO;
	if (ptpip_set_nonblock(params->cmdfd) == -1) { PTPSOCK_CLOSE(params->cmdfd); return GP_ERROR_IO; }
	params->evtfd = socket (PF_INET, SOCK_STREAM, 0);
	if (params->evtfd == PTPSOCK_INVALID) { PTPSOCK_CLOSE(params->cmdfd); return GP_ERROR_IO; }
	if (ptpip_set_nonblock(params->evtfd) == -1) { PTPSOCK_CLOSE(params->cmdfd); PTPSOCK_CLOSE(params->evtfd); return GP_ERROR_IO; }

	if (ptpip_connect_with_timeout (params->cmdfd, (struct sockaddr*)&saddr, sizeof(saddr), 5, 0) == -1) {
		ptp_ptpip_disconnect(params);
		return GP_ERROR_IO;
	}

	ret = nikonptpip_init_command_request (params);
	if (ret != PTP_RC_OK) { ptp_ptpip_disconnect(params); return translate_ptp_result(ret); }
	ret = nikonptpip_init_command_ack (params);
	if (ret != PTP_RC_OK) { ptp_ptpip_disconnect(params); return translate_ptp_result(ret); }
	
	if (ptpip_connect_with_timeout (params->evtfd, (struct sockaddr*)&saddr, sizeof(saddr), 5, 0) == -1) {
		ptp_ptpip_disconnect(params);
		return GP_ERROR_IO;
	}

	ret = nikonptpip_init_event_request (params);
	if (ret != PTP_RC_OK) { ptp_ptpip_disconnect(params); return translate_ptp_result(ret); }
	ret = nikonptpip_init_event_ack (params);
	if (ret != PTP_RC_OK) { ptp_ptpip_disconnect(params); return translate_ptp_result(ret); }

	GP_LOG_D ("Nikon PTP/IP STA mode connected!");
	return GP_OK;
}
