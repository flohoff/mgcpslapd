#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>

#include "logging.h"

void dump_hex(int level, const char *prefix, uint8_t *buf, int size) {
	int		i;
	unsigned char	ch;
	char		sascii[17];
	char		linebuffer[16*4+1];

	/* Speedup */
	if (level > loglevel)
		return;

	sascii[16]=0x0;

	for(i=0;i<size;i++) {
		ch=buf[i];
		if (i%16 == 0) {
			sprintf(linebuffer, "%04x ", i);
		}
		sprintf(&linebuffer[(i%16)*3], "%02x ", ch);
		if (ch >= ' ' && ch <= '}')
			sascii[i%16]=ch;
		else
			sascii[i%16]='.';

		if (i%16 == 15)
			_logwrite(NULL, 0, level, "%s %s  %s", prefix, linebuffer, sascii);
	}

	/* i++ after loop */
	if (i%16 != 0) {
		for(;i%16 != 0;i++) {
			sprintf(&linebuffer[(i%16)*3], "   ");
			sascii[i%16]=' ';
		}

		_logwrite(NULL, 0, level, "%s %s  %s", prefix, linebuffer, sascii);
	}
}
