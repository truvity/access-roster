package nats_test

import "os"

func writeFile(name, body string) error { return os.WriteFile(name, []byte(body), 0o600) }
