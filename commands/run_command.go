package runCommand

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime/pprof"
	"time"
	"unsafe"

	git "github.com/dickmao/git2go"
	"github.com/urfave/cli"
)

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

func RunCommand() *cli.Command {
	return &cli.Command{
		Name:  "run",
		Flags: runFlags(),
		Action: func(c *cli.Context) error {
			// fmt.Println("Bad Bad Leroy Brown: ", c.Args().First())
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
			git_dir, err := git.Discover("./test-repo", true, nil)
			if err != nil {
				panic(err)
			}
			repo, _ := git.OpenRepository(git_dir)
			defer repo.Free()
			git_dir1, err := git.Discover(filepath.Join(repo.Workdir(), ".gat"),
				true, nil)
			var repo1 *git.Repository
			if err != nil {
				repo1, err = git.Clone(git_dir,
					filepath.Join(repo.Workdir(), ".gat"),
					&git.CloneOptions{Bare: true})
				if err != nil {
					panic(err)
				}
			} else {
				repo1, _ = git.OpenRepository(git_dir1)
			}
			config, err := repo1.Config()
			if err != nil {
				panic(err)
			}
			config.SetString("remote.origin.fetch",
				"refs/heads/*:refs/heads/*")
			sig := &git.Signature{
				Name:  "-",
				Email: "-",
				When:  time.Now()}
			oid, err := repo.Stashes.Save(
				sig, "", git.StashDefault|git.StashKeepIndex|git.StashIncludeUntracked)
			if err != nil {
				panic(err)
			}
			odb, err := repo.Odb()
			if err != nil {
				panic(err)
			}
			rannum := rand.Uint64()
			bs := make([]byte, unsafe.Sizeof(rannum))
			binary.LittleEndian.PutUint64(bs, rannum)
			oid, err = odb.Hash(bs, git.ObjectCommit)
			if err != nil {
				panic(err)
			}
			branchName := fmt.Sprintf("gat-%s", oid)[0:14]
			commit, _ := headCommit(repo)
			defer commit.Free()
			to_delete, err := repo.CreateBranch(branchName, commit, false)
			if err != nil {
				panic(err)
			}
			defer to_delete.Free()
			to_return, err := repo.Head()
			if err != nil {
				panic(err)
			}
			defer to_return.Free()
			// checkout -b gat-7e5d856631
			repo.SetHead(to_delete.Reference.Name())
			opts, _ := git.DefaultStashApplyOptions()
			// stash apply
			if err = repo.Stashes.Apply(0, opts); err != nil {
				panic(err)
			}
			idx, err := repo.Index()
			if err != nil {
				panic(err)
			}
			// stage
			if err = idx.UpdateAll([]string{"."}, nil); err != nil {
				panic(err)
			}
			treeID, _ := idx.WriteTree()
			tree, err := repo.LookupTree(treeID)
			if err != nil {
				panic(err)
			}
			// commit
			currentTip, err := repo.LookupCommit(to_delete.Target())
			if oid, err = repo.CreateCommit("HEAD", sig, sig, "squirrel",
				tree, currentTip); err != nil {
				panic(err)
			}
			// okay, gat-7e5d856631 made
			// to_return kept unstaged changes, so no need to pop
			repo.SetHead(to_return.Name())
			if err = repo.Stashes.Drop(0); err != nil {
				panic(err)
			}
			if err = os.MkdirAll(filepath.Join(repo1.Path(), "objects/pack"),
				os.ModePerm); err != nil {
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
			if _, err = git.AddWorktree(repo1, branchName, filepath.Join(repo1.Path(), ref.Shorthand()), options); err != nil {
				panic(err)
			}
			// tree, err := commit.Tree()
			// repo.CheckoutTree(tree, &CheckoutOpts{Strategy: CheckoutSafe})
			return nil
		},
	}
}

func runFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "cpuprofile",
			Usage:   "write cpu profile to file",
			EnvVars: []string{"CPU_PROFILE"},
		},
	}
}
