//go:build (!(linux && amd64) && !(windows && amd64)) || encz_dynamic

package encz

/*
#cgo CFLAGS: -I${SRCDIR} -DSQLITE_CORE=1 -DSQLITE_CRYPTOVFS_STATIC=1
#cgo LDFLAGS: -lcrypto
*/
import "C"
