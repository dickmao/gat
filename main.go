package main

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	commands "github.com/dickmao/gat/commands"
	git "github.com/dickmao/git2go"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func discoverOrigin(path string) (string, error) {
	git_dir, err := git.Discover(path, true, nil)
	if err != nil {
		panic(err)
	}
	if filepath.Base(filepath.Clean(git_dir)) == ".gat" {
		git_dir, err = git.Discover(filepath.Dir(filepath.Clean(git_dir)),
			true, nil)
	}
	return git_dir, err
}

func main() {
	// r, _ := git.PlainOpenWithOptions(".", &git.PlainOpenOptions{DetectDotGit: true})
	// headRef, _ := r.Head()
	// ref := plumbing.NewHashReference("refs/heads/my-branch", headRef.Hash())
	// r.Storer.SetReference(ref)

	logrus.SetLevel(logrus.InfoLevel)
	logrus.SetOutput(os.Stdout)

	rand.Seed(time.Now().UnixNano())

	app := cli.NewApp()
	app.Commands = []*cli.Command{
		commands.CreateCommand(),
		commands.TestCommand(),
		commands.EditCommand(),
		commands.ListCommand(),
	}
	app.ExitErrHandler = func(context *cli.Context, err error) {
		if err == nil {
			return
		}
		if exitErr, ok := err.(cli.ExitCoder); ok {
			if exitErr.ExitCode() == 7 {
				fmt.Fprintln(app.Writer, err)
				cli.OsExiter(exitErr.ExitCode())
				return
			}
		}
		cli.HandleExitCoder(err)
	}
	app.Action = func(c *cli.Context) error {
		cli.ShowAppHelpAndExit(c, -1)
		return nil
	}

	git_dir, err := discoverOrigin(".")
	if err != nil {
		panic(err)
	}
	repo, err := git.OpenRepository(filepath.Clean(git_dir))
	if err != nil {
		panic(err)
	}
	defer repo.Free()

	if worktree, err := repo.NewWorktreeFromSubrepository(); err == nil {
		defer worktree.Free()
		if git_dir, err =
			discoverOrigin(filepath.Dir(filepath.Clean(git_dir))); err != nil {
			panic(err)
		}
		repo, err = git.OpenRepository(filepath.Clean(git_dir))
		if err != nil {
			panic(err)
		}
		defer repo.Free()
	}

	git_dir1, err := git.Discover(filepath.Join(repo.Workdir(), ".gat"),
		true, nil)
	var repo1 *git.Repository
	if err != nil {
		panic(err)
	} else {
		repo1, err = git.OpenRepository(filepath.Clean(git_dir1))
		if err != nil {
			panic(err)
		}
	}
	defer repo1.Free()
	ignored, err := repo.IsPathIgnored(".gat")
	if err != nil {
		panic(err)
	}
	if !(ignored) {
		if err = repo.AddIgnoreRule(".gat"); err != nil {
			panic(err)
		}
	}
	if err = os.MkdirAll(filepath.Join(repo1.Path(), "objects/pack"),
		os.ModePerm); err != nil {
		panic(err)
	}
	if err = app.RunContext(commands.NewContext(repo, repo1), os.Args); err != nil {
		panic(err)
	}
}
