package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/urfave/cli/v2"
)

func TestCreate(t *testing.T) {
	t.Parallel()
	repo := createTestRepo(t)
	defer cleanupTestRepo(t, repo)
	seedTestRepo(t, repo)
	os.Chdir(filepath.Clean(repo.Path()))

	app := newApp()
	app.ExitErrHandler = func(context *cli.Context, err error) {
		return
	}
	err := app.Run(
		[]string{app.Name, "--project", "project_test", "--zone", "zone_test",
			"--region", "us-central", "create", "foobar"})
	if err.(cli.ExitCoder).ExitCode() != 7 {
		t.Error("create should return 7")
	}
}
