package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	commands "github.com/dickmao/gat/commands"

	git "github.com/dickmao/git2go/v31"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

//go:generate go run cos_gpu_installer_generate/cos_gpu_installer_generate.go

func getRepo(path string, config *git.Config) (*git.Repository, error) {
	var (
		repo   *git.Repository
		reterr error
	)
	git_dir, err := git.Discover(path, true, nil)
	if err != nil {
		if err.(*git.GitError).Code == git.ErrNotFound {
			repo, reterr = git.InitRepository(path, false)
		} else {
			panic(err)
		}
	} else {
		if filepath.Base(filepath.Clean(git_dir)) == ".gat" {
			git_dir, err = git.Discover(filepath.Dir(filepath.Clean(git_dir)), true, nil)
			if err != nil {
				panic(err)
			}
		}
		repo, reterr = git.OpenRepository(filepath.Clean(git_dir))
	}

	if reterr == nil {
		head, err := repo.Head()
		if head != nil {
			defer head.Free()
		}
		if err != nil && git.IsErrorClass(err, git.ErrClassReference) {
			if idx, err := repo.Index(); err == nil {
				defer idx.Free()
				idx.UpdateAll([]string{"."}, nil)
				idx.AddAll([]string{"."}, git.IndexAddDefault, nil)
				var name, email string
				if name, err = config.LookupString("user.name"); err != nil {
					name = "gat"
				}
				if email, err = config.LookupString("user.email"); err != nil {
					email = "none"
				}
				sig := &git.Signature{
					Name:  name,
					Email: email,
					When:  time.Now()}
				if treeID, err := idx.WriteTree(); err != nil {
					panic(err)
				} else if tree, err := repo.LookupTree(treeID); err != nil {
					panic(err)
				} else {
					if err := idx.Write(); err != nil {
						panic(err)
					}
					if _, err := repo.CreateCommit("HEAD", sig, sig, fmt.Sprintf("gat create %s", commands.MasterWorktree), tree); err != nil {
						panic(err)
					}
				}
			}
		}
	}
	return repo, reterr
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
		commands.MasterCommand(),
		commands.CreateCommand(),
		commands.RegistryCommand(),
		commands.LogCommand(),
		commands.TestCommand(),
		commands.VersionCommand(),
		commands.SendgridCommand(),
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
	var config *git.Config
	if config_loc, err := git.ConfigFindGlobal(); err != nil {
		if err.(*git.GitError).Code == git.ErrNotFound {
			if c, err := git.NewConfig(); err != nil {
				panic(err)
			} else {
				config = c
			}
		} else {
			panic(err)
		}
	} else if c, err := git.OpenOndisk(config_loc); err != nil {
		panic(err)
	} else {
		config = c
	}
	repo, err := getRepo(dir, config)
	if err != nil {
		panic(err)
	}
	worktree, err := repo.NewWorktreeFromSubrepository()
	if err == nil {
		repo, err = getRepo(filepath.Dir(filepath.Clean(repo.Workdir())), config)
		if err != nil {
			panic(err)
		}
	}
	gat_path := filepath.Join(repo.Workdir(), ".gat")
	git_dir1, err := git.Discover(gat_path, true, nil)
	var repo1 *git.Repository
	if err != nil {
		if err.(*git.GitError).Code == git.ErrNotFound {
			repo1, err = git.Clone(repo.Path(), gat_path, &git.CloneOptions{Bare: true})
		}
	} else {
		repo1, err = git.OpenRepository(filepath.Clean(git_dir1))
	}
	if err != nil {
		panic(err)
	}
	for _, r := range []*git.Repository{repo, repo1} {
		if err = r.AddIgnoreRule(strings.Join([]string{".gat", "run-local", "run-remote"}, "\n")); err != nil {
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
