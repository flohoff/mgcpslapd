#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/time.h>
#include <time.h>

#include "logging.h"

int loglevel=LOG_DEBUG;

void logwrite_inc_level() {
	loglevel++;
}

void _logwrite(const char *function, int line, int level, const char *format, ...) {
	va_list		pvar;
	char		logbuffer[MAXPATHLEN];
	char		timedate[64];
	struct timeval	tv;
	struct tm	*tm;
	time_t		*t=&tv.tv_sec;

	if (level > loglevel)
		return;

	va_start (pvar, format);
	vsnprintf(logbuffer, sizeof(logbuffer), format, pvar);
	va_end (pvar);

	gettimeofday(&tv, NULL);
	tm=localtime(t);

	strftime(timedate, sizeof(timedate), "%Y-%m-%d %H:%M:%S", tm);

	if (function)
		printf("%s.%03d %s/%d %s\n",
				timedate,
				(int) tv.tv_usec/1000,
				function,
				line,
				logbuffer);
	else
		printf("%s.%03d %s\n",
				timedate,
				(int) tv.tv_usec/1000,
				logbuffer);

}
