package commands

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"cloud.google.com/go/storage"
	git "github.com/dickmao/git2go"
	"github.com/docker/distribution"
	"github.com/docker/distribution/reference"
	v2 "github.com/docker/distribution/registry/api/v2"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/docker/distribution/registry/client/transport"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/docker/docker/pkg/term"
	"github.com/docker/docker/registry"
	digest "github.com/opencontainers/go-digest"
	"github.com/urfave/cli/v2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
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
	resourceManagerService     *cloudresourcemanager.Service
	computeService             *compute.Service
	containerService           *container.Service
	storageClient              *storage.Client
	resourceManagerServiceOnce sync.Once
	computeServiceOnce         sync.Once
	containerServiceOnce       sync.Once
	storageClientOnce          sync.Once
)

type ServiceAccount struct {
	Type           string
	Project_id     string
	Private_key_id string
	Client_email   string
	Client_id      string
}

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

func gatId(c *cli.Context) string {
	return c.String("project") + "-" + strings.ReplaceAll(constructTag(c), ":", "-")
}

func ensureBucket(c *cli.Context) error {
	bucket := getClientStorage().Bucket(gatId(c))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	if err := bucket.Create(ctx, c.String("project"), &storage.BucketAttrs{}); err != nil {
		if err.(*googleapi.Error).Code == 409 {
			return nil
		}
		return err
	}
	return nil
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

func getClientStorage() *storage.Client {
	storageClientOnce.Do(func() {
		ensureApplicationDefaultCredentials()
		var err error
		if storageClient, err = storage.NewClient(context.Background()); err != nil {
			panic(err)
		}
	})
	return storageClient
}

func getServiceResourceManager() *cloudresourcemanager.Service {
	resourceManagerServiceOnce.Do(func() {
		ensureApplicationDefaultCredentials()
		ctx := context.Background()

		creds, err := google.FindDefaultCredentials(ctx, cloudresourcemanager.CloudPlatformScope)
		if err != nil {
			panic(err)
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
	computeServiceOnce.Do(func() {
		ensureApplicationDefaultCredentials()
		ctx := context.Background()
		creds, err := google.FindDefaultCredentials(ctx, compute.CloudPlatformScope)
		if err != nil {
			panic(err)
		}
		computeService, err =
			compute.NewService(ctx, option.WithCredentials(creds))
		if computeService == nil {
			panic("why")
		}
		if err != nil {
			panic(err)
		}
	})
	return computeService
}

func getContainerService() *container.Service {
	containerServiceOnce.Do(func() {
		ensureApplicationDefaultCredentials()
		ctx := context.Background()

		creds, err := google.FindDefaultCredentials(ctx, container.CloudPlatformScope)
		if err != nil {
			panic(err)
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

func PingV2Registry(endpoint *url.URL, transport http.RoundTripper) (challenge.Manager, error) {
	pingClient := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}
	endpointStr := strings.TrimRight(endpoint.String(), "/") + "/v2/"
	req, err := http.NewRequest(http.MethodGet, endpointStr, nil)
	if err != nil {
		return nil, err
	}
	resp, err := pingClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	challengeManager := challenge.NewSimpleManager()
	if err := challengeManager.AddResponse(resp); err != nil {
		return nil, registry.PingResponseError{
			Err: err,
		}
	}

	return challengeManager, nil
}

func descriptorFromResponse(response *http.Response) (distribution.Descriptor, error) {
	desc := distribution.Descriptor{}
	headers := response.Header

	ctHeader := headers.Get("Content-Type")
	if ctHeader == "" {
		return distribution.Descriptor{}, errors.New("missing or empty Content-Type header")
	}
	desc.MediaType = ctHeader

	digestHeader := headers.Get("Docker-Content-Digest")
	if digestHeader == "" {
		bytes, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return distribution.Descriptor{}, err
		}
		_, desc, err := distribution.UnmarshalManifest(ctHeader, bytes)
		if err != nil {
			return distribution.Descriptor{}, err
		}
		return desc, nil
	}

	desc.Digest = *(*digest.Digest)(unsafe.Pointer(&digestHeader))
	lengthHeader := headers.Get("Content-Length")
	if lengthHeader == "" {
		return distribution.Descriptor{}, errors.New("missing or empty Content-Length header")
	}
	length, err := strconv.ParseInt(lengthHeader, 10, 64)
	if err != nil {
		return distribution.Descriptor{}, err
	}
	desc.Size = length

	return desc, nil

}

func TestCommand() *cli.Command {
	return &cli.Command{
		Name: "test",
		Action: func(c *cli.Context) error {
			// project := c.String("project")
			// repo := c.Context.Value(repoKey).(*git.Repository)
			if err := ensureBucket(c); err != nil {
				panic(err)
			}

			project := c.String("project")
			repo := c.Context.Value(repoKey).(*git.Repository)
			name, err := reference.WithName(filepath.Join("gcr.io", project, filepath.Base(filepath.Clean(repo.Workdir()))))
			if err != nil {
				panic(err)
			}
			repoInfo, err := registry.ParseRepositoryInfo(name)
			if err != nil {
				panic(err)
			}
			// registryService can only search for stars
			registryService, err := registry.NewService(registry.ServiceOptions{
				InsecureRegistries: []string{"gcr.io"},
			})
			if err != nil {
				panic(err)
			}
			endpoints, err := registryService.LookupPushEndpoints(reference.Domain(repoInfo.Name))
			if err != nil {
				panic(err)
			}
			// Default to the highest priority endpoint to return
			if !repoInfo.Index.Secure {
				for _, ep := range endpoints {
					if ep.URL.Scheme == "http" {
						endpoints[0] = ep
					}
				}
			}
			base := &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				Dial: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
					DualStack: true,
				}).Dial,
				TLSHandshakeTimeout: 10 * time.Second,
				TLSClientConfig:     endpoints[0].TLSConfig,
				DisableKeepAlives:   true,
			}
			authTransport := transport.NewTransport(base)
			challengeManager, err := PingV2Registry(endpoints[0].URL, authTransport)
			if err != nil {
				panic(err)
			}
			bytes, err := ioutil.ReadFile(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
			if err != nil {
				panic(err)
			}
			creds := registry.NewStaticCredentialStore(&types.AuthConfig{
				ServerAddress: "gcr.io",
				Username:      "_json_key",
				Password:      string(bytes),
			})
			justpath, err := reference.WithName(reference.Path(name))
			if err != nil {
				panic(err)
			}
			tokenHandler := auth.NewTokenHandler(authTransport, creds, justpath.Name(), "push", "pull")
			basicHandler := auth.NewBasicHandler(creds)
			authTransport = transport.NewTransport(base, auth.NewAuthorizer(challengeManager, tokenHandler, basicHandler))
			client := &http.Client{Transport: authTransport}
			ub, err := v2.NewURLBuilderFromString(endpoints[0].URL.String(), false)

			mfstURLStr, err := ub.BuildManifestURL(justpath)
			if err != nil {
				panic(err)
			}

			newRequest := func(method string) (*http.Response, error) {
				req, err := http.NewRequest(method, mfstURLStr, nil)
				if err != nil {
					return nil, err
				}

				for _, t := range distribution.ManifestMediaTypes() {
					req.Header.Add("Accept", t)
				}
				resp, err := client.Do(req)
				return resp, err
			}

			resp, err := newRequest("HEAD")
			if err != nil {
				panic(err)
			}
			defer resp.Body.Close()
			switch {
			case resp.StatusCode >= 200 && resp.StatusCode < 400 && len(resp.Header.Get("Docker-Content-Digest")) > 0:
				// if the response is a success AND a Docker-Content-Digest can be retrieved from the headers
				if desc, err := descriptorFromResponse(resp); err != nil {
					panic(err)
				} else {
					fmt.Println(desc)
				}
			default:
				// if the response is an error - there will be no body to decode.
				// Issue a GET request:
				//   - for data from a server that does not handle HEAD
				//   - to get error details in case of a failure
				resp, err = newRequest("GET")
				if err != nil {
					panic(err)
				}
				defer resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 400 {
					if desc, err := descriptorFromResponse(resp); err != nil {
						panic(err)
					} else {
						fmt.Println(desc)
					}
				}
			}

			// listURLStr, err := ub.BuildTagsURL(justpath)
			// if err != nil {
			// 	panic(err)
			// }
			// listURL, err := url.Parse(listURLStr)
			// if err != nil {
			// 	panic(err)
			// }
			// var tags []string
			// for {
			// 	resp, err := client.Get(listURL.String())
			// 	if err != nil {
			// 		panic(err)
			// 	}
			// 	defer resp.Body.Close()
			// 	if distributionclient.SuccessStatus(resp.StatusCode) {
			// 		b, err := ioutil.ReadAll(resp.Body)
			// 		if err != nil {
			// 			panic(err)
			// 		}
			// 		tagsResponse := struct {
			// 			Tags []string `json:"tags"`
			// 		}{}
			// 		if err := json.Unmarshal(b, &tagsResponse); err != nil {
			// 			panic(err)
			// 		}
			// 		tags = append(tags, tagsResponse.Tags...)
			// 		if link := resp.Header.Get("Link"); link != "" {
			// 			linkURLStr := strings.Trim(strings.Split(link, ";")[0], "<>")
			// 			linkURL, err := url.Parse(linkURLStr)
			// 			if err != nil {
			// 				panic(err)
			// 			}

			// 			listURL = listURL.ResolveReference(linkURL)
			// 			continue
			// 		}
			// 	}
			// 	break
			// }
			// fmt.Println(tags)
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

func PushCommand() *cli.Command {
	return &cli.Command{
		Name: "push",
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
			if err := pushImage(project, constructTag(c)); err != nil {
				panic(err)
			}
			return nil
		},
	}
}

func RunRemoteCommand() *cli.Command {
	return &cli.Command{
		Name: "run-remote",
		Action: func(c *cli.Context) error {
			repo := c.Context.Value(repoKey).(*git.Repository)
			repo1 := c.Context.Value(repo1Key).(*git.Repository)
			worktree := c.Context.Value(worktreeKey).(*git.Worktree)
			config := c.Context.Value(configKey).(*git.Config)
			project := c.String("project")
			zone := c.String("zone")
			if err := c.App.RunContext(NewContext(repo, repo1, worktree, config),
				[]string{c.App.Name, "--project", project, "--zone", zone, "push"}); err != nil {
				panic(err)
			}
			config1, err := repo1.Config()
			if err != nil {
				panic(err)
			}
			config1.SetString("remote.origin.fetch", "refs/heads/*:refs/heads/*")
			config1.SetString("gat.last_project", project)

			if err = ensureBucket(c); err != nil {
				panic(err)
			}

			prefix := "https://www.googleapis.com/compute/v1/projects/" + project
			bytes, err := ioutil.ReadFile(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
			if err != nil {
				panic(err)
			}
			quoted_escaped := strconv.Quote(string(bytes))
			modifier_escaped := strings.Replace(quoted_escaped[1:len(quoted_escaped)-1], "%", "%%", -1)
			newline_escaped := strings.Replace(modifier_escaped, "\\\\n", "\\\\\\\\n", -1)
			cloudconfig := CloudConfig{project, constructTag(c), gatId(c), os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"), newline_escaped}
			user_data := UserData(cloudconfig)
			shutdown_script := Shutdown(cloudconfig)
			var serviceAccount ServiceAccount
			json.Unmarshal(bytes, &serviceAccount)
			instance := &compute.Instance{
				Name:        gatId(c),
				Description: "compute sample instance",
				MachineType: prefix + "/zones/" + zone + "/machineTypes/n1-standard-1",
				Metadata: &compute.Metadata{
					Items: []*compute.MetadataItems{
						{
							Key:   "user-data",
							Value: &user_data,
						},
						{
							Key:   "shutdown-script",
							Value: &shutdown_script,
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
						Email: serviceAccount.Client_email,
						Scopes: []string{
							compute.DevstorageFullControlScope,
							compute.ComputeScope,
							iam.CloudPlatformScope,
						},
					},
				},
			}
			instancesService := compute.NewInstancesService(getService())
			if _, err = instancesService.Insert(project, zone, instance).Context(context.Background()).Do(); err != nil {
				panic(err)
			}
			return nil
		},
	}
}

func RunLocalCommand() *cli.Command {
	return &cli.Command{
		Name: "run-local",
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

			// would use docker cp but won't know WORKDIR
			// docker -v dirname(GOOGLE_APPLICATION_CREDENTIALS):/stash --rm --entrypoint "/bin/cp" tag -c "/stash/basename(GOOGLE_APPLICATION_CREDENTIALS) ."
			// docker commit carcass to-run
			// docker run --privileged --rm to-run

			return nil
		},
	}
}

func pushImage(project string, tag string) error {
	ensureApplicationDefaultCredentials()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}
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

	if _, err := cli.ImagesPrune(context.Background(),
		filters.NewArgs(filters.Arg("label", "gat="+tag))); err != nil {
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
	termFd, isTerm := term.GetFdInfo(os.Stderr)
	if err = jsonmessage.DisplayJSONMessagesStream(pushBody, os.Stderr, termFd, isTerm, nil); err != nil {
		panic(err)
	}
	return nil
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
	buildResponse, err := cli.ImageBuild(context.Background(), buildContext, types.ImageBuildOptions{Tags: []string{tag}, ForceRemove: true,
		Labels: map[string]string{
			"gat": tag,
		}})
	if err != nil {
		panic(err)
	}
	defer buildResponse.Body.Close()
	termFd, isTerm := term.GetFdInfo(os.Stderr)
	if err := jsonmessage.DisplayJSONMessagesStream(buildResponse.Body, os.Stderr, termFd, isTerm, nil); err != nil {
		panic(err)
	}
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
