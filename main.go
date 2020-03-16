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

func getRepo(path string) (*git.Repository, error) {
	git_dir, err := git.Discover(path, true, nil)
	if err != nil {
		panic(err)
	}
	if filepath.Base(filepath.Clean(git_dir)) == ".gat" {
		git_dir, err = git.Discover(filepath.Dir(filepath.Clean(git_dir)),
			true, nil)
		if err != nil {
			panic(err)
		}
	}
	return git.OpenRepository(filepath.Clean(git_dir))
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

	repo, err := getRepo(".")
	if err != nil {
		panic(err)
	}
	defer repo.Free()

	worktree, err := repo.NewWorktreeFromSubrepository()
	if err == nil {
		defer worktree.Free()
		repo, err = getRepo(filepath.Dir(filepath.Clean(repo.Workdir())))
		if err != nil {
			panic(err)
		}
		defer repo.Free()
	}

	gat_path := filepath.Join(repo.Workdir(), ".gat")
	git_dir1, err := git.Discover(gat_path, true, nil)
	var repo1 *git.Repository
	if err != nil {
		repo1, err = git.Clone(repo.Path(), gat_path, &git.CloneOptions{Bare: true})
		if err != nil {
			panic(err)
		}
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
	config, err := repo1.Config()
	if err != nil {
		panic(err)
	}
	config.SetString("remote.origin.fetch", "refs/heads/*:refs/heads/*")
	if err = app.RunContext(commands.NewContext(repo, repo1, worktree), os.Args); err != nil {
		panic(err)
	}
}
