package encz

import "C"

import (
	"log"
	"strings"
)

// LogHandler is called whenever the underlying C extension encounters an error
// (such as page decryption failure or MAC verification failure).
// If nil, errors are logged using standard Go log package.
var LogHandler func(string)

//export enczGoLog
func enczGoLog(msg *C.char) {
	str := strings.TrimSpace(C.GoString(msg))
	if LogHandler != nil {
		LogHandler(str)
	} else {
		log.Println(str)
	}
}
