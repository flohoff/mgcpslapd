
extern int loglevel;

void logwrite_inc_level(void );
#define logwrite(...) \
	_logwrite(__FUNCTION__, __LINE__, ##__VA_ARGS__)
void _logwrite(const char *function, int line, int level, const char *format, ...);

enum {
	LOG_ERROR,
	LOG_INFO,
	LOG_DEBUG,
	LOG_EVENT,
	LOG_XTREME,
};

