package sqliteseal

import "C"

import (
	"log"
	"strings"
	"sync/atomic"
)

var logHandler atomic.Pointer[func(string)]

// SetLogHandler sets a custom handler for encz error messages
// (such as page decryption failure or MAC verification failure).
// Pass nil to revert to the default (log.Println) behavior.
func SetLogHandler(h func(string)) {
	if h == nil {
		logHandler.Store(nil)
	} else {
		logHandler.Store(&h)
	}
}

//export enczGoLog
func enczGoLog(msg *C.char) {
	str := strings.TrimSpace(C.GoString(msg))
	if hp := logHandler.Load(); hp != nil {
		(*hp)(str)
	} else {
		log.Println(str)
	}
}
