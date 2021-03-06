package snmpclient

// #include <stdint.h>
// #include <sys/types.h>
// #include <string.h>
// #include <stdlib.h>
// #include <string.h>
//
// #include "bsnmp/config.h"
// #include <stdlib.h>
// #include "bsnmp/asn1.h"
// #include "bsnmp/snmp.h"
import "C"

import (
	"errors"
	"expvar"
	"strconv"
	"sync"
	"sync/atomic"
	"unsafe"
)

type AtomicInt struct{}

func (v *AtomicInt) String() string {
	return strconv.FormatInt(int64(atomic.LoadInt32(&malloc_count)), 10)
}

var malloc_count int32 = 0

func init() {
	expvar.Publish("malloc_count", &AtomicInt{})
}

//export IncrementMemory
func IncrementMemory() {
	atomic.AddInt32(&malloc_count, 1)
}

//export DecrementMemory
func DecrementMemory() {
	atomic.AddInt32(&malloc_count, -1)
}

func memcpy(dst *C.uint8_t, capacity int, src []byte) error {
	if 0 == len(src) {
		return nil
	}
	if capacity < len(src) {
		return errors.New("bytes too long.")
	}

	C.memcpy(unsafe.Pointer(dst), unsafe.Pointer(&src[0]), C.size_t(len(src)))
	return nil
}

func readGoBytes(src *C.uint8_t, length C.uint32_t) []byte {

	if 0 == length {
		return []byte{}
	}

	return C.GoBytes(unsafe.Pointer(src), C.int(length))
}

func readGoString(src *C.char, capacity int) string {
	if 0 == capacity {
		return ""
	}
	length := int(C.strlen(src))
	if capacity < length {
		panic("string too long.")
		return "" //errors.New("string too long.")
	}
	return C.GoStringN(src, C.int(length))
}

func strcpy(dst *C.char, capacity int, src string) error {
	if 0 == len(src) {
		return nil
	}
	if capacity < len(src) {
		return errors.New("string too long.")
	}
	s := C.CString(src)
	//IncrementMemory()
	C.strcpy(dst, s)
	C.free(unsafe.Pointer(s))
	//DecrementMemory()
	return nil
}

const pdu_cache_size = 20

var (
	native_pdu_mutex sync.Mutex
	native_pdu_cache = newNativePduBuffer(make([]*C.snmp_pdu_t, pdu_cache_size))
)

func newNativePdu() *C.snmp_pdu_t {
	native_pdu_mutex.Lock()
	cached := native_pdu_cache.Pop()
	native_pdu_mutex.Unlock()
	if nil != cached {
		return cached
	}
	return C.snmp_pdu_new()
}

func releaseNativePdu(will_cache *C.snmp_pdu_t) {
	C.snmp_pdu_zero(will_cache)
	native_pdu_mutex.Lock()
	if pdu_cache_size > native_pdu_cache.Size() {
		native_pdu_cache.Push(will_cache)
	} else {
		C.snmp_pdu_destroy(will_cache)
	}
	native_pdu_mutex.Unlock()
}
