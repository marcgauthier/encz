//go:build linux && amd64 && !encz_dynamic

package sqliteseal

/*
#cgo CFLAGS: -I${SRCDIR} -I${SRCDIR}/lib/include -DSQLITE_CORE=1 -DSQLITE_CRYPTOVFS_STATIC=1
#cgo LDFLAGS:
*/
import "C"
