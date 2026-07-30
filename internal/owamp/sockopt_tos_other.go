//go:build !windows && !linux && !darwin

package owamp

func setTOSFD(uintptr, int) error     { return nil }
func setSendTTLFD(uintptr, int) error { return nil }
