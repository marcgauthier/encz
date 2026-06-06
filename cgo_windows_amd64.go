//go:build windows && amd64 && !encz_dynamic

package encz

/*
#cgo CFLAGS: -I${SRCDIR} -DSQLITE_CORE=1 -DSQLITE_CRYPTOVFS_STATIC=1
#cgo LDFLAGS: -L${SRCDIR}/lib/windows_amd64 -lcrypto
*/
import "C"
