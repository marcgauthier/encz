package encz

/*
#include "sqlite3.h"

int sqlite3_register_encz(const char *);

static int encz_register_once(void) {
	return sqlite3_register_encz(0);
}
*/
import "C"

import (
	"fmt"
	"sync"
)

var (
	registerEnczOnce sync.Once
	registerEnczErr  error
)

func registerEncz() error {
	registerEnczOnce.Do(func() {
		rc := int(C.encz_register_once())
		if rc != int(C.SQLITE_OK) {
			registerEnczErr = fmt.Errorf("sqlite3_register_encz failed: %d", rc)
		}
	})
	return registerEnczErr
}
