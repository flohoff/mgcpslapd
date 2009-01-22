#include <strings.h>

#include "valstring.h"

const char *vstr_val2str(valstring *list, int value, const char *def) {
	while(list->str && list->value != value)
		list++;

	if (list->str)
		return list->str;

	return def;
}

int vstr_str2val(char *str, valstring *list, int *value) {
	while(list->str) {
		if (!strcasecmp(list->str, str)) {
			*value=list->value;
			return 1;
		}
		list++;
	}

	return 0;
}
