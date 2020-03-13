package commands

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"time"

	git "github.com/dickmao/git2go"
	"github.com/urfave/cli"
)

type wrapper struct {
	context.Context
	repo, repo1 *git.Repository
}

type key int

const repoKey key = 0
const repo1Key key = 1

func NewContext(repo *git.Repository, repo1 *git.Repository) context.Context {
	return &wrapper{context.Background(), repo, repo1}
}

func (ctx *wrapper) Value(key interface{}) interface{} {
	switch key {
	case repoKey:
		return ctx.repo
	case repo1Key:
		return ctx.repo1
	default:
		return ctx.Context.Value(key)
	}
}

func headCommit(repo *git.Repository) (*git.Commit, error) {
	head, err := repo.Head()
	if err != nil {
		return nil, err
	}
	defer head.Free()

	commit, err := repo.LookupCommit(head.Target())
	if err != nil {
		return nil, err
	}

	return commit, nil
}

func TestCommand() *cli.Command {
	return &cli.Command{
		Name: "test",
		Action: func(c *cli.Context) error {
			if worktrees, err := c.Context.Value(repo1Key).(*git.Repository).ListWorktrees(); err != nil {
				panic(err)
			} else {
				fmt.Println(worktrees)
			}
			return nil
		},
	}
}

func CreateCommand() *cli.Command {
	return &cli.Command{
		Name:  "create",
		Flags: createFlags(),
		Action: func(c *cli.Context) error {
			if cpuProfile := c.String("cpuprofile"); cpuProfile != "" {
				f, err := os.Create(cpuProfile)
				if err != nil {
					panic(err)
				}
				defer f.Close()
				if err := pprof.StartCPUProfile(f); err != nil {
					panic(err)
				}
				defer pprof.StopCPUProfile()
			}
			repo := c.Context.Value(repoKey).(*git.Repository)
			repo1 := c.Context.Value(repo1Key).(*git.Repository)
			to_return, err := repo.Head()
			if err != nil {
				panic(err)
			}
			defer to_return.Free()
			sig := &git.Signature{
				Name:  "-",
				Email: "-",
				When:  time.Now()}
			_, err = repo.Stashes.Save(
				sig, "", git.StashDefault|git.StashKeepIndex|git.StashIncludeUntracked)
			if err != nil {
				panic(err)
			}
			opts, _ := git.DefaultStashApplyOptions()

			branchName := c.Args().Get(0)
			if branchName == "" {
				scanner := bufio.NewScanner(os.Stdin)
				scanner.Scan()
				if err := scanner.Err(); err != nil {
					repo.Stashes.Pop(0, opts)
					panic(err)
				}
				branchName = scanner.Text()
			}

			if old_branch, err := repo1.LookupBranch(branchName, git.BranchLocal); err == nil {
				defer old_branch.Free()
				repo.Stashes.Pop(0, opts)
				panic(fmt.Sprintf("Extant branch \"%v\"", branchName))
			}

			commit, err := headCommit(repo)
			if err != nil {
				panic(err)
			}
			defer commit.Free()
			to_delete, err := repo.CreateBranch(branchName, commit, false)
			if err != nil {
				repo.Stashes.Pop(0, opts)
				panic(err)
			}
			defer to_delete.Free()
			// checkout -b gat-7e5d856631
			repo.SetHead(to_delete.Reference.Name())
			// stash apply
			if err = repo.Stashes.Apply(0, opts); err != nil {
				repo.Stashes.Pop(0, opts)
				panic(err)
			}
			idx, err := repo.Index()
			if err != nil {
				repo.Stashes.Pop(0, opts)
				panic(err)
			}
			defer idx.Free()
			// stage
			if err = idx.UpdateAll([]string{"."}, nil); err != nil {
				repo.Stashes.Pop(0, opts)
				panic(err)
			}
			treeID, _ := idx.WriteTree()
			tree, err := repo.LookupTree(treeID)
			if err != nil {
				repo.Stashes.Pop(0, opts)
				panic(err)
			}
			// commit
			currentTip, err := repo.LookupCommit(to_delete.Target())
			if _, err := repo.CreateCommit("HEAD", sig, sig, "squirrel",
				tree, currentTip); err != nil {
				repo.Stashes.Pop(0, opts)
				panic(err)
			}
			// okay, gat-7e5d856631 made
			repo.SetHead(to_return.Name())
			if err = repo.CheckoutHead(&git.CheckoutOpts{Strategy: git.CheckoutRemoveUntracked}); err != nil {
				repo.Stashes.Pop(0, opts)
				panic(err)
			}
			if err = repo.ResetToCommit(commit, git.ResetHard, &git.CheckoutOpts{Strategy: git.CheckoutForce}); err != nil {
				repo.Stashes.Pop(0, opts)
				panic(err)
			}

			// if err = idx.Clear(); err != nil {
			// 	panic(err)
			// }
			// if err = idx.Write(); err != nil {
			// 	panic(err)
			// }
			if err = repo.Stashes.Pop(0, opts); err != nil {
				panic(err)
			}
			remote, err := repo1.Remotes.Lookup("origin")
			if err != nil {
				panic(err)
			}
			err = remote.Fetch([]string{}, &git.FetchOptions{}, "")
			if err != nil {
				panic(err)
			}
			// cannot Delete() to_delete as reference changed
			to_delete, err = repo.LookupBranch(branchName, git.BranchLocal)
			if err != nil {
				panic(err)
			}
			defer to_delete.Free()
			if err = to_delete.Delete(); err != nil {
				panic(err)
			}

			ref, err := repo1.References.Dwim(branchName)
			if err != nil {
				panic(err)
			}
			defer ref.Free()

			options, err := git.NewWorktreeAddOptions(1, 0, ref)
			if err != nil {
				panic(err)
			}
			if _, err := repo1.AddWorktree(branchName, filepath.Join(repo1.Path(), ref.Shorthand()), options); err != nil {
				panic(err)
			}

			return nil
		},
	}
}

func createFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "cpuprofile",
			Usage:   "write cpu profile to file",
			EnvVars: []string{"CPU_PROFILE"},
		},
	}
}

func ListCommand() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Flags: listFlags(),
		Action: func(c *cli.Context) error {
			repo1 := c.Context.Value(repo1Key).(*git.Repository)
			brit, err := repo1.NewBranchIterator(git.BranchLocal)
			if err != nil {
				panic(err)
			}
			defer brit.Free()
			if err = brit.ForEach(
				func(br *git.Branch, _ty git.BranchType) error {
					if name, err := br.Name(); err != nil {
						return err
					} else {
						fmt.Println(name)
					}
					return nil
				}); err != nil {
				panic(err)
			}
			return nil
		},
	}
}

func EditCommand() *cli.Command {
	return &cli.Command{
		Name:  "edit",
		Flags: editFlags(),
		Action: func(c *cli.Context) error {
			if cpuProfile := c.String("cpuprofile"); cpuProfile != "" {
				f, err := os.Create(cpuProfile)
				if err != nil {
					panic(err)
				}
				defer f.Close()
				if err := pprof.StartCPUProfile(f); err != nil {
					panic(err)
				}
				defer pprof.StopCPUProfile()
			}
			repo1 := c.Context.Value(repo1Key).(*git.Repository)
			worktreeName := c.Args().Get(0)
			if worktreeName == "" {
				scanner := bufio.NewScanner(os.Stdin)
				scanner.Scan()
				if err := scanner.Err(); err != nil {
					panic(err)
				}
				worktreeName = scanner.Text()
			}
			_, err := repo1.LookupBranch(worktreeName, git.BranchLocal)
			if err != nil {
				panic(err)
			}
			wtnames, err := repo1.ListWorktrees()
			var worktree *git.Worktree
			for _, wtname := range wtnames {
				if wtname == worktreeName {
					worktree, err = repo1.LookupWorktree(wtname)
					if err != nil {
						panic(err)
					}
					defer worktree.Free()
				}
			}
			if worktree == nil {
				ref, err := repo1.References.Dwim(worktreeName)
				if err != nil {
					panic(err)
				}
				defer ref.Free()
				options, err := git.NewWorktreeAddOptions(1, 0, ref)
				if err != nil {
					panic(err)
				}
				if worktree, err = repo1.AddWorktree(worktreeName, filepath.Join(repo1.Path(), ref.Shorthand()), options); err != nil {
					panic(err)
				}
			}
			return cli.NewExitError(fmt.Sprintf("cd %s", worktree.Path()), 7)
		},
	}
}

func editFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "cpuprofile",
			Usage:   "write cpu profile to file",
			EnvVars: []string{"CPU_PROFILE"},
		},
	}
}

func listFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "cpuprofile",
			Usage:   "write cpu profile to file",
			EnvVars: []string{"CPU_PROFILE"},
		},
	}
}
