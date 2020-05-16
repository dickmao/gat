package main

import (
	"fmt"
	"os"
	"path/filepath"

	commands "github.com/dickmao/gat/commands"

	git "github.com/dickmao/git2go/v31"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
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

func newApp() *cli.App {
	app := cli.NewApp()

	// source-gat will force-populate these if user doesn't specify
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:     "project",
			Required: true,
			Aliases:  []string{"p"},
			Usage:    "gcp project",
		},
		&cli.StringFlag{
			Name:     "zone",
			Required: true,
			Aliases:  []string{"z"},
			Usage:    "gcp zone",
		},
		&cli.StringFlag{
			Name:     "region",
			Required: true,
			Aliases:  []string{"r"},
			Usage:    "gcp region",
		},
	}
	app.Commands = []*cli.Command{
		commands.CreateCommand(),
		commands.RegistryCommand(),
		commands.TestCommand(),
		commands.RunRemoteCommand(),
		commands.RunLocalCommand(),
		commands.DockerfileCommand(),
		commands.BuildCommand(),
		commands.PushCommand(),
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
	return app
}

func initGat(dir string) (*git.Repository, *git.Repository, *git.Worktree, *git.Config) {
	repo, err := getRepo(dir)
	if err != nil {
		panic(err)
	}
	worktree, err := repo.NewWorktreeFromSubrepository()
	if err == nil {
		repo, err = getRepo(filepath.Dir(filepath.Clean(repo.Workdir())))
		if err != nil {
			panic(err)
		}
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
	config1, err := repo1.Config()
	if err != nil {
		panic(err)
	}
	config1.SetString("remote.origin.fetch", "refs/heads/*:refs/heads/*")

	config_loc, err := git.ConfigFindGlobal()
	if err != nil {
		panic(err)
	}
	config, err := git.OpenOndisk(config_loc)
	if err != nil {
		panic(err)
	}
	return repo, repo1, worktree, config
}

func main() {
	// r, _ := git.PlainOpenWithOptions(".", &git.PlainOpenOptions{DetectDotGit: true})
	// headRef, _ := r.Head()
	// ref := plumbing.NewHashReference("refs/heads/my-branch", headRef.Hash())
	// r.Storer.SetReference(ref)
	logrus.SetLevel(logrus.InfoLevel)
	logrus.SetOutput(os.Stdout)

	repo, repo1, worktree, config := initGat(".")
	defer repo.Free()
	defer repo1.Free()
	defer config.Free()
	if worktree != nil {
		defer worktree.Free()
	}
	if err := newApp().RunContext(commands.NewContext(repo, repo1, worktree, config), os.Args); err != nil {
		panic(err)
	}
}
