//go:build !unix && !windows

package auth

import "os"

func lockFile(*os.File) error { return nil }

func unlockFile(*os.File) error { return nil }
