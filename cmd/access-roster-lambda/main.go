// Command access-roster-lambda is the Lambda extension that sends a
// function's OTLP data with the function role's identity. It is installed
// as /opt/extensions/access-roster-otlp; see docs/integrations/aws-lambda.md.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/truvity/observability/lambdaext"
)

func main() { os.Exit(run()) }

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	err := lambdaext.Run(ctx, lambdaext.Options{
		Getenv: os.Getenv,
		Logf:   log.Printf,
		// The platform matches the registered name to the file name.
		Name: filepath.Base(os.Args[0]),
	})
	if err != nil {
		log.Printf("access-roster-otlp: %v", err)
		return 1
	}
	return 0
}
