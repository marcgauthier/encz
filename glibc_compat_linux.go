//go:build linux

package encz

/*
#include <stdlib.h>

long __isoc23_strtol(const char *nptr, char **endptr, int base) {
	return strtol(nptr, endptr, base);
}
*/
import "C"
