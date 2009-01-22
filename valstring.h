#include <stdint.h>

typedef struct {
	uint32_t	value;
	const char	*str;
} valstring;

int vstr_str2val(char *str, valstring *list, int *value);
const char *vstr_val2str(valstring *list, int value, const char *def);
