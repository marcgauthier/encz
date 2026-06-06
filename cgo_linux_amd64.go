//go:build linux && amd64 && !encz_dynamic

package encz

/*
#cgo CFLAGS: -I${SRCDIR} -I${SRCDIR}/lib/include -DSQLITE_CORE=1 -DSQLITE_CRYPTOVFS_STATIC=1
#cgo LDFLAGS: -L${SRCDIR}/lib/linux_amd64 -lcrypto -Wl,-rpath,${SRCDIR}/lib/linux_amd64 -Wl,--disable-new-dtags
*/
import "C"
