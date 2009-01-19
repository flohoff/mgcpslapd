#include <strings.h>

#include "valstring.h"

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
