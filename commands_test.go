package main

import (
	"testing"

	commands "github.com/dickmao/gat/commands"
	"github.com/urfave/cli/v2"
)

func TestCreate(t *testing.T) {
	t.Parallel()
	repo := createTestRepo(t)
	defer cleanupTestRepo(t, repo)
	seedTestRepo(t, repo)

	repo, repo1, worktree, config := initGat(repo.Workdir())
	defer repo.Free()
	defer repo1.Free()
	defer config.Free()
	if worktree != nil {
		defer worktree.Free()
	}
	app := newApp()
	app.ExitErrHandler = func(context *cli.Context, err error) {
		return
	}
	err := app.RunContext(commands.NewContext(repo, repo1, worktree, config),
		[]string{app.Name, "--project", "project_test", "--zone", "zone_test",
			"create", "foobar"})
	if err.(cli.ExitCoder).ExitCode() != 7 {
		t.Error("create should return 7")
	}
}
