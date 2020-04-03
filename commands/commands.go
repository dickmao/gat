package commands

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime/pprof"
	"sync"
	"time"

	git "github.com/dickmao/git2go"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/docker/docker/pkg/term"
	"github.com/urfave/cli"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/option"
)

type wrapper struct {
	context.Context
	repo, repo1 *git.Repository
	worktree    *git.Worktree
	config      *git.Config
}

type key int

const repoKey key = 0
const repo1Key key = 1
const worktreeKey key = 2
const configKey key = 3

var (
	resourceManagerService *cloudresourcemanager.Service
	computeService         *compute.Service
	containerService       *container.Service
	once                   sync.Once
)

func processCpuProfileFlag(c *cli.Context) {
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
}

func NewContext(repo *git.Repository, repo1 *git.Repository, worktree *git.Worktree, config *git.Config) context.Context {
	return &wrapper{context.Background(), repo, repo1, worktree, config}
}

func (ctx *wrapper) Value(key interface{}) interface{} {
	switch key {
	case repoKey:
		return ctx.repo
	case repo1Key:
		return ctx.repo1
	case worktreeKey:
		return ctx.worktree
	case configKey:
		return ctx.config
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

func ensureApplicationDefaultCredentials() {
	if _, ok := os.LookupEnv("GOOGLE_APPLICATION_CREDENTIALS"); !ok {
		panic("Must currently set GOOGLE_APPLICATION_CREDENTIALS to service_account.json")
	}
}

func getServiceResourceManager() *cloudresourcemanager.Service {
	once.Do(func() {
		ensureApplicationDefaultCredentials()
		ctx := context.Background()

		creds, err := google.FindDefaultCredentials(ctx, cloudresourcemanager.CloudPlatformScope)
		if err != nil {
			log.Fatal(err)
		}
		resourceManagerService, err =
			cloudresourcemanager.NewService(context.Background(), option.WithCredentials(creds))
		if err != nil {
			panic(err)
		}
	})
	return resourceManagerService
}

func getService() *compute.Service {
	once.Do(func() {
		ensureApplicationDefaultCredentials()
		ctx := context.Background()

		creds, err := google.FindDefaultCredentials(ctx, compute.CloudPlatformScope)
		if err != nil {
			log.Fatal(err)
		}
		computeService, err =
			compute.NewService(context.Background(), option.WithCredentials(creds))
		if err != nil {
			panic(err)
		}
	})
	return computeService
}

func getContainerService() *container.Service {
	once.Do(func() {
		ensureApplicationDefaultCredentials()
		ctx := context.Background()

		creds, err := google.FindDefaultCredentials(ctx, container.CloudPlatformScope)
		if err != nil {
			log.Fatal(err)
		}
		containerService, err =
			container.NewService(context.Background(), option.WithCredentials(creds))
		if err != nil {
			panic(err)
		}
	})
	return containerService
}

func getBranchRepo(c *cli.Context) *git.Repository {
	repo := c.Context.Value(repoKey).(*git.Repository)
	worktree := c.Context.Value(worktreeKey).(*git.Worktree)
	var branch_repo *git.Repository
	if worktree != nil {
		branch_repo = worktree.Repo
	} else {
		branch_repo = repo
	}
	return branch_repo
}

func constructTag(c *cli.Context) string {
	branch_repo := getBranchRepo(c)
	head, err := branch_repo.Head()
	if err != nil {
		panic(err)
	}
	defer head.Free()
	ref, err := head.Resolve()
	if err != nil {
		panic(err)
	}
	defer ref.Free()
	repo := c.Context.Value(repoKey).(*git.Repository)
	return filepath.Base(filepath.Clean(repo.Workdir())) + ":" + ref.Shorthand()
}

func TestCommand() *cli.Command {
	return &cli.Command{
		Name: "test",
		Action: func(c *cli.Context) error {
			project := c.String("project")
			if err := buildImage(project, constructTag(c)); err != nil {
				panic(err)
			}
			return nil
		},
	}
}

func BuildCommand() *cli.Command {
	return &cli.Command{
		Name: "build",
		Action: func(c *cli.Context) error {
			project := c.String("project")
			if err := buildImage(project, constructTag(c)); err != nil {
				panic(err)
			}
			return nil
		},
	}
}

func RunCommand() *cli.Command {
	return &cli.Command{
		Name: "run",
		Action: func(c *cli.Context) error {
			repo := c.Context.Value(repoKey).(*git.Repository)
			repo1 := c.Context.Value(repo1Key).(*git.Repository)
			worktree := c.Context.Value(worktreeKey).(*git.Worktree)
			config := c.Context.Value(configKey).(*git.Config)
			project := c.String("project")
			zone := c.String("zone")
			if err := c.App.RunContext(NewContext(repo, repo1, worktree, config),
				[]string{c.App.Name, "--project", project, "--zone", zone, "build"}); err != nil {
				panic(err)
			}
			config1, err := repo1.Config()
			if err != nil {
				panic(err)
			}
			config1.SetString("remote.origin.fetch", "refs/heads/*:refs/heads/*")
			config1.SetString("gat.last_project", project)

			prefix := "https://www.googleapis.com/compute/v1/projects/" + project

			user_data := cloudConfig(CloudConfig{project, constructTag(c)})
			branch_repo := getBranchRepo(c)
			head, err := branch_repo.Head()
			if err != nil {
				panic(err)
			}
			defer head.Free()
			ref, err := head.Resolve()
			if err != nil {
				panic(err)
			}
			defer ref.Free()
			instance := &compute.Instance{
				Name:        project + "-" + ref.Shorthand(),
				Description: "compute sample instance",
				MachineType: prefix + "/zones/" + zone + "/machineTypes/n1-standard-1",
				Metadata: &compute.Metadata{
					Items: []*compute.MetadataItems{
						{
							Key:   "user-data",
							Value: &user_data,
						},
					},
				},
				Scheduling: &compute.Scheduling{
					Preemptible: true,
				},
				Disks: []*compute.AttachedDisk{
					{
						AutoDelete: true,
						Boot:       true,
						Type:       "PERSISTENT",
						InitializeParams: &compute.AttachedDiskInitializeParams{

							SourceImage: "projects/cos-cloud/global/images/family/cos-beta",
						},
					},
				},
				NetworkInterfaces: []*compute.NetworkInterface{
					{
						AccessConfigs: []*compute.AccessConfig{
							{
								Type: "ONE_TO_ONE_NAT",
								Name: "External NAT",
							},
						},
						Network: prefix + "/global/networks/default",
					},
				},
				ServiceAccounts: []*compute.ServiceAccount{
					{
						Email: "service-account@api-project-421333809285.iam.gserviceaccount.com",
						Scopes: []string{
							compute.DevstorageFullControlScope,
							compute.ComputeScope,
						},
					},
				},
			}
			instancesService := compute.NewInstancesService(getService())
			instancesService.Insert(project, zone, instance)
			_, err = instancesService.Insert(project, zone, instance).Context(context.Background()).Do()
			if err != nil {
				panic(err)
			}
			return nil
		},
	}
}

func buildImage(project string, tag string) error {
	ensureApplicationDefaultCredentials()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}
	// remotecontext.MakeGitRepo(gitURL) clones and tars
	// say file://./my-repo.git#branch but I need unstaged changes too
	buildContext, err := archive.TarWithOptions(".", &archive.TarOptions{})
	if err != nil {
		panic(err)
	}
	defer buildContext.Close()
	buildResponse, err := cli.ImageBuild(context.Background(), buildContext, types.ImageBuildOptions{Tags: []string{tag}, ForceRemove: true})
	if err != nil {
		panic(err)
	}
	defer buildResponse.Body.Close()
	termFd, isTerm := term.GetFdInfo(os.Stderr)
	jsonmessage.DisplayJSONMessagesStream(buildResponse.Body, os.Stderr, termFd, isTerm, nil)

	if images, err := cli.ImageList(context.Background(),
		types.ImageListOptions{Filters: filters.NewArgs(filters.Arg("reference", tag))}); err != nil || len(images) == 0 {
		if len(images) == 0 {
			panic(fmt.Sprintf("Image tagged %s not found", tag))
		} else {
			panic(err)
		}
	}
	target := filepath.Join("gcr.io", project, tag)
	err = cli.ImageTag(context.Background(), tag, target)
	if err != nil {
		panic(err)
	}

	bytes, err := ioutil.ReadFile(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
	if err != nil {
		panic(err)
	}
	jsonBytes, _ := json.Marshal(map[string]string{
		"username": "_json_key",
		"password": string(bytes),
	})

	pushBody, err := cli.ImagePush(context.Background(), target,
		types.ImagePushOptions{
			RegistryAuth: base64.StdEncoding.EncodeToString(jsonBytes),
		})
	if err != nil {
		panic(err)
	}
	defer pushBody.Close()
	jsonmessage.DisplayJSONMessagesStream(pushBody, os.Stderr, termFd, isTerm, nil)
	return nil
}

func CreateFromRepo(c *cli.Context) (string, error) {
	repo := c.Context.Value(repoKey).(*git.Repository)
	repo1 := c.Context.Value(repo1Key).(*git.Repository)
	config := c.Context.Value(configKey).(*git.Config)
	to_return, err := repo.Head()
	if err != nil {
		panic(err)
	}
	defer to_return.Free()
	name, _ := config.LookupString("user.name")
	email, _ := config.LookupString("user.email")
	sig := &git.Signature{
		Name:  name,
		Email: email,
		When:  time.Now()}
	stash_oid, _ := repo.Stashes.Save(
		sig, "", git.StashDefault|git.StashKeepIndex|git.StashIncludeUntracked)
	opts, _ := git.DefaultStashApplyOptions()

	branchName := c.Args().Get(0)
	if branchName == "" {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		if err := scanner.Err(); err != nil {
			if stash_oid != nil {
				repo.Stashes.Pop(0, opts)
			}
			panic(err)
		}
		branchName = scanner.Text()
	}
	if old_branch, err := repo1.LookupBranch(branchName, git.BranchLocal); err == nil {
		defer old_branch.Free()
		if stash_oid != nil {
			repo.Stashes.Pop(0, opts)
		}
		panic(fmt.Sprintf("Extant branch \"%v\"", branchName))
	}

	commit, err := headCommit(repo)
	if err != nil {
		if stash_oid != nil {
			repo.Stashes.Pop(0, opts)
		}
		panic(err)
	}
	defer commit.Free()
	to_delete, err := repo.CreateBranch(branchName, commit, false)
	if err != nil {
		if stash_oid != nil {
			repo.Stashes.Pop(0, opts)
		}
		panic(err)
	}
	defer to_delete.Free()

	if stash_oid != nil {
		repo.SetHead(to_delete.Reference.Name())
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
		if _, err := repo.CreateCommit("HEAD", sig, sig, fmt.Sprintf("gat create %s", branchName),
			tree, currentTip); err != nil {
			repo.Stashes.Pop(0, opts)
			panic(err)
		}
		// restore master
		repo.SetHead(to_return.Name())
		if err = repo.CheckoutHead(&git.CheckoutOpts{Strategy: git.CheckoutRemoveUntracked}); err != nil {
			repo.Stashes.Pop(0, opts)
			panic(err)
		}
		if err = repo.ResetToCommit(commit, git.ResetHard, &git.CheckoutOpts{Strategy: git.CheckoutForce}); err != nil {
			repo.Stashes.Pop(0, opts)
			panic(err)
		}
		if err = repo.Stashes.Pop(0, opts); err != nil {
			panic(err)
		}
		// cannot Delete() to_delete as reference changed
		to_delete, err = repo.LookupBranch(branchName, git.BranchLocal)
		if err != nil {
			panic(err)
		}
		defer to_delete.Free()
	}
	remote, err := repo1.Remotes.Lookup("origin")
	if err != nil {
		panic(err)
	}
	err = remote.Fetch([]string{}, &git.FetchOptions{}, "")
	if err != nil {
		panic(err)
	}
	if err = to_delete.Delete(); err != nil {
		panic(err)
	}
	// add worktree
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
	return branchName, nil
}

func CreateFromWorktree(c *cli.Context) (string, error) {
	repo1 := c.Context.Value(repo1Key).(*git.Repository)
	worktree := c.Context.Value(worktreeKey).(*git.Worktree)
	config := c.Context.Value(configKey).(*git.Config)
	to_return, err := worktree.Repo.Head()
	if err != nil {
		panic(err)
	}
	defer to_return.Free()
	name, _ := config.LookupString("user.name")
	email, _ := config.LookupString("user.email")
	sig := &git.Signature{
		Name:  name,
		Email: email,
		When:  time.Now()}
	stash_oid, _ := worktree.Repo.Stashes.Save(
		sig, "", git.StashDefault|git.StashKeepIndex|git.StashIncludeUntracked)
	opts, _ := git.DefaultStashApplyOptions()

	branchName := c.Args().Get(0)
	if branchName == "" {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		if err := scanner.Err(); err != nil {
			panic(err)
		}
		branchName = scanner.Text()
	}

	if old_branch, err := repo1.LookupBranch(branchName, git.BranchLocal); err == nil {
		defer old_branch.Free()
		if stash_oid != nil {
			worktree.Repo.Stashes.Pop(0, opts)
		}
		panic(fmt.Sprintf("Extant branch \"%v\"", branchName))
	}

	// i need the commit of worktree
	commit, err := headCommit(worktree.Repo)
	if err != nil {
		if stash_oid != nil {
			worktree.Repo.Stashes.Pop(0, opts)
		}
		panic(err)
	}
	defer commit.Free()

	new_branch, err := repo1.CreateBranch(branchName, commit, false)
	if err != nil {
		if stash_oid != nil {
			worktree.Repo.Stashes.Pop(0, opts)
		}
		panic(err)
	}
	defer new_branch.Free()

	options, err := git.NewWorktreeAddOptions(1, 0, new_branch.Reference)
	if err != nil {
		if stash_oid != nil {
			worktree.Repo.Stashes.Pop(0, opts)
		}
		panic(err)
	}
	repo1_worktree, err := repo1.AddWorktree(branchName, filepath.Join(repo1.Path(), new_branch.Reference.Shorthand()), options)
	if err != nil {
		if stash_oid != nil {
			worktree.Repo.Stashes.Pop(0, opts)
		}
		panic(err)
	}
	defer repo1_worktree.Free()

	if stash_oid != nil {
		repo2, err := git.OpenRepository(filepath.Clean(repo1_worktree.Path()))
		if err != nil {
			if stash_oid != nil {
				worktree.Repo.Stashes.Pop(0, opts)
			}
			panic(err)
		}
		defer repo2.Free()

		new_worktree, err := repo2.NewWorktreeFromSubrepository()
		if err != nil {
			if stash_oid != nil {
				worktree.Repo.Stashes.Pop(0, opts)
			}
			panic(err)
		}
		defer new_worktree.Free()

		if err = new_worktree.Repo.Stashes.Apply(0, opts); err != nil {
			worktree.Repo.Stashes.Pop(0, opts)
			panic(err)
		}
		worktree.Repo.Stashes.Pop(0, opts)

		// stage
		idx, err := new_worktree.Repo.Index()
		if err != nil {
			panic(err)
		}
		defer idx.Free()
		if err = idx.UpdateAll([]string{"."}, nil); err != nil {
			panic(err)
		}
		if err = idx.Write(); err != nil {
			panic(err)
		}
		treeID, _ := idx.WriteTree()
		tree, err := new_worktree.Repo.LookupTree(treeID)
		if err != nil {
			panic(err)
		}
		// commit
		currentTip, err := new_worktree.Repo.LookupCommit(new_branch.Target())
		if _, err := new_worktree.Repo.CreateCommit("HEAD", sig, sig, fmt.Sprintf("gat create %s", branchName),
			tree, currentTip); err != nil {
			panic(err)
		}
	}
	return branchName, nil
}

func CreateCommand() *cli.Command {
	return &cli.Command{
		Name:  "create",
		Flags: createFlags(),
		Action: func(c *cli.Context) error {
			processCpuProfileFlag(c)
			var branchName string
			var err error
			if worktree := c.Context.Value(worktreeKey).(*git.Worktree); worktree != nil {
				branchName, err = CreateFromWorktree(c)
				if err != nil {
					panic(err)
				}
			} else {
				branchName, err = CreateFromRepo(c)
				if err != nil {
					panic(err)
				}
			}

			repo := c.Context.Value(repoKey).(*git.Repository)
			repo1 := c.Context.Value(repo1Key).(*git.Repository)
			worktree := c.Context.Value(worktreeKey).(*git.Worktree)
			config := c.Context.Value(configKey).(*git.Config)
			project := c.String("project")
			zone := c.String("zone")
			return c.App.RunContext(NewContext(repo, repo1, worktree, config),
				[]string{c.App.Name, "--project", project, "--zone", zone, "edit", branchName})
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
			processCpuProfileFlag(c)
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
