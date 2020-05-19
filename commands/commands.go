package commands

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
	"unsafe"

	"cloud.google.com/go/logging/logadmin"
	"cloud.google.com/go/storage"
	git "github.com/dickmao/git2go/v31"
	"github.com/docker/distribution"
	"github.com/docker/distribution/reference"
	v2 "github.com/docker/distribution/registry/api/v2"
	distributionclient "github.com/docker/distribution/registry/client"
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
	"github.com/docker/go-units"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	godigest "github.com/opencontainers/go-digest"
	"github.com/urfave/cli/v2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudfunctions/v1"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/pubsub/v1"
)

type digest struct {
	// ImageSizeBytes string   `json:"imageSizeBytes"`
	// LayerId        string   `json:"layerId"`
	MediaType string   `json:"mediaType"`
	Tags      []string `json:"tag"`
	// TimeCreatedMs  string   `json:"timeCreatedMs"`
	// TimeUploadedMs string   `json:"timeUploadedMs"`
}

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
	myAuthn                    *authn.Basic
	resourceManagerServiceOnce sync.Once
	computeServiceOnce         sync.Once
	containerServiceOnce       sync.Once
	storageClientOnce          sync.Once
	myAuthnOnce                sync.Once
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

func getMyAuthn() *authn.Basic {
	myAuthnOnce.Do(func() {
		ensureApplicationDefaultCredentials()
		bytes, err := ioutil.ReadFile(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
		if err != nil {
			panic(err)
		}
		myAuthn = &authn.Basic{Username: "_json_key", Password: string(bytes)}
	})
	return myAuthn
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

func branchReference(c *cli.Context) (*git.Reference, error) {
	branch_repo := getBranchRepo(c)
	head, err := branch_repo.Head()
	if err != nil {
		panic(err)
	}
	defer head.Free()
	return head.Resolve()
}

func constructTag(c *cli.Context) string {
	ref, err := branchReference(c)
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

	desc.Digest = *(*godigest.Digest)(unsafe.Pointer(&digestHeader))
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

func getImage(project string, tag string) v1.Image {
	refTag, err := name.ParseReference(filepath.Join("gcr.io", project, tag))
	if err != nil {
		panic(err)
	}
	img, _ := remote.Image(refTag, remote.WithAuth(getMyAuthn()))
	return img
}

func deleteImage(project string, tag string, digest v1.Hash) error {
	refDig, err := name.ParseReference(filepath.Join("gcr.io", project, tag[:strings.IndexByte(tag, ':')]+"@"+digest.String()))
	if err != nil {
		panic(err)
	}
	if err = remote.Delete(refDig, remote.WithAuth(getMyAuthn())); err != nil {
		panic(err)
	}
	return nil
}

func requiredHack(c *cli.Context, cmd string, args []string) []string {
	if c.Args().Len() != len(args) {
		// https://github.com/urfave/cli/pull/140#issuecomment-131841364
		bracketed := make([]string, len(args))
		for i, v := range args {
			bracketed[i] = fmt.Sprintf("<%s>", v)
		}
		cli.CommandHelpTemplate = strings.Replace(cli.CommandHelpTemplate, "[arguments...]", strings.Join(bracketed, " "), -1)
		cli.ShowCommandHelpAndExit(c, cmd, -1)
	}
	required := make([]string, len(args))
	for i, _ := range args {
		required[i] = c.Args().Get(i)
	}
	return required
}

func escapeCredentials() ([]byte, string, error) {
	bytes, err := ioutil.ReadFile(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
	if err != nil {
		return bytes, "", err
	}
	quoted_escaped := strconv.Quote(string(bytes))
	modifier_escaped := strings.Replace(quoted_escaped[1:len(quoted_escaped)-1], "%", "%%", -1)
	newline_escaped := strings.Replace(modifier_escaped, "\\\\n", "\\\\\\\\n", -1)
	return bytes, newline_escaped, nil
}

func TestCommand() *cli.Command {
	return &cli.Command{
		Name: "test",
		Action: func(c *cli.Context) error {
			return nil
		},
	}
}

func SendgridCommand() *cli.Command {
	return &cli.Command{
		Name:  "sendgrid",
		Flags: sendgridFlags(),
		Action: func(c *cli.Context) error {
			project := c.String("project")
			topic := url.Values{}
			topic.Set("topic", "compute.googleapis.com/activity_log")
			serviceAccountBytes, _, _ := escapeCredentials()
			var serviceAccount ServiceAccount
			json.Unmarshal(serviceAccountBytes, &serviceAccount)
			client, err := logadmin.NewClient(context.Background(), project)
			if err != nil {
				panic(err)
			}
			sink_id := "gat-activity-log"
			sink, err := client.Sink(context.Background(), sink_id)
			if err != nil {
				if _, err = client.CreateSinkOpt(context.Background(), &logadmin.Sink{
					ID:          sink_id,
					Destination: fmt.Sprintf("pubsub.googleapis.com/projects/%s/topics/%s", project, sink_id),
					Filter:      fmt.Sprintf("logName = projects/%s/logs/%s", project, topic.Encode()[strings.Index(topic.Encode(), "=")+1:]),
				}, logadmin.SinkOptions{
					UniqueWriterIdentity: true,
				}); err != nil {
					panic(err)
				}
			}

			// ProjectsLocationsFunctions
			topic_id := fmt.Sprintf("projects/%s/topics/%s", project, sink_id)
			if s, err := cloudfunctions.NewService(context.Background()); err != nil {
				panic(err)
			} else {
				service := cloudfunctions.NewProjectsLocationsFunctionsService(s)
				region := c.String("region")
				parent := fmt.Sprintf("projects/%s/locations/%s", project, region)
				func_id := fmt.Sprintf("%s/functions/gat-activity-log", parent)
				if existing, err := service.Get(func_id).Do(); err != nil && err.(*googleapi.Error).Code/100 != 2 && err.(*googleapi.Error).Code != 404 {
					panic(err)
				} else if existing != nil {
					if op, err := service.Delete(func_id).Do(); err != nil {
						panic(err)
					} else {
						done, errstatus := waitOp(s, op.Name, 60, 2000)
						if !done {
							panic("Delete() timed out")
						} else if errstatus != nil {
							panic(fmt.Sprintf("Delete() returned %d", errstatus.Code))
						}
					}
				}

				respUrl, err := service.GenerateUploadUrl(parent, &cloudfunctions.GenerateUploadUrlRequest{}).Do()
				if err != nil {
					panic(err)
				}
				data := new(bytes.Buffer)
				zipw := zip.NewWriter(data)
				if f, err := zipw.Create("hello_pubsub.go"); err != nil {
					zipw.Close()
					panic(err)
				} else if _, err = f.Write(PubSubSource(c, c.String("api-key"))); err != nil {
					zipw.Close()
					panic(err)
				}
				if f, err := zipw.Create("go.mod"); err != nil {
					zipw.Close()
					panic(err)
				} else if _, err = f.Write(PubSubGoMod(c)); err != nil {
					zipw.Close()
					panic(err)
				}
				if err = zipw.Close(); err != nil {
					panic(err)
				}
				req, err := http.NewRequest(http.MethodPut, respUrl.UploadUrl, data)
				if err != nil {
					panic(err)
				}
				req.Header.Set("Content-Type", "application/zip")
				req.Header.Set("x-goog-content-length-range", "0,104857600")
				client := &http.Client{}
				respReq, err := client.Do(req)
				if err != nil {
					panic(err)
				} else if respReq.StatusCode != http.StatusOK {
					panic(fmt.Sprintf("status %s", respReq.StatusCode))
				}
				cf := &cloudfunctions.CloudFunction{
					Name:            func_id,
					SourceUploadUrl: respUrl.UploadUrl,
					EntryPoint:      "HelloPubSub",
					Runtime:         "go111",
					EventTrigger: &cloudfunctions.EventTrigger{
						EventType: "providers/cloud.pubsub/eventTypes/topic.publish",

						Resource: topic_id,
					},
				}
				if op, err := service.Create(parent, cf).Do(); err != nil {
					panic(err)
				} else {
					done, errstatus := waitOp(s, op.Name, 60, 2000)
					if !done {
						panic("Create() timed out")
					} else if errstatus != nil {
						panic(fmt.Sprintf("Create(): %s, code %d", errstatus.Message, errstatus.Code))
					}
				}
			}

			// Topics
			if s, err := pubsub.NewService(context.Background()); err != nil {
				panic(err)
			} else {
				service := pubsub.NewProjectsTopicsService(s)
				if opolicy, err := service.GetIamPolicy(topic_id).Do(); err != nil {
					panic(err)
				} else if npolicy, err := service.SetIamPolicy(topic_id, &pubsub.SetIamPolicyRequest{
					Policy: &pubsub.Policy{
						Bindings: []*pubsub.Binding{
							&pubsub.Binding{
								Members: []string{sink.WriterIdentity},
								Role:    "roles/pubsub.publisher",
							},
						},
						Etag: opolicy.Etag,
					},
				}).Do(); err != nil {
					panic(err)
				} else {
					fmt.Println(npolicy)
				}
			}

			if err := client.Close(); err != nil {
				panic(err)
			}
			// logsink := &logging.LogSink{
			// 	Name:           "gat-activity-log",
			// 	Description:    "gat log sink",
			// 	Destination:    fmt.Sprintf("pubsub.googleapis.com/projects/%s/topics/gat-activity-log", project),
			// 	Filter:         fmt.Sprintf("logName = projects/%s/logs/%s", project, topic.Encode()[strings.Index(topic.Encode(), "=")+1:]),
			// 	WriterIdentity: serviceAccount.Client_email,
			// }
			// loggingService, _ := logging.NewService(ctx)
			// logging.NewSinksService(loggingService).Create(

			return nil
		},
	}
}

func RegistryCommand() *cli.Command {
	return &cli.Command{
		Name: "registry",
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
			listURLStr, err := ub.BuildTagsURL(justpath)
			if err != nil {
				panic(err)
			}
			listURL, err := url.Parse(listURLStr)
			if err != nil {
				panic(err)
			}
			ref, err := branchReference(c)
			if err != nil {
				panic(err)
			}
			defer ref.Free()

			branch := ref.Shorthand()
			var digestToDelete digest
			var shaToDelete string
		done:
			for {
				resp, err := client.Get(listURL.String())
				if err != nil {
					panic(err)
				}
				defer resp.Body.Close()
				if distributionclient.SuccessStatus(resp.StatusCode) {
					b, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						panic(err)
					}
					digestsResponse := struct {
						Digest map[string]digest `json:"manifest"`
					}{}
					if err := json.Unmarshal(b, &digestsResponse); err != nil {
						panic(err)
					}
					for sha, dig := range digestsResponse.Digest {
						for _, tag := range dig.Tags {
							if tag == branch {
								digestToDelete = dig
								shaToDelete = sha
								break done
							}
						}
					}
					if link := resp.Header.Get("Link"); link != "" {
						linkURLStr := strings.Trim(strings.Split(link, ";")[0], "<>")
						linkURL, err := url.Parse(linkURLStr)
						if err != nil {
							panic(err)
						}

						listURL = listURL.ResolveReference(linkURL)
						continue
					}
				}
				break
			}
			if len(shaToDelete) > 0 {
				// cannot authenticate distributionclient.NewRepository
				repo, err := distributionclient.NewRepository(justpath, endpoints[0].URL.String(), registry.NewTransport(nil))
				if err != nil {
					panic(err)
				}
				ctx := context.Background()
				ms, err := repo.Manifests(ctx)
				if err != nil {
					panic(err)
				}
				if err = ms.Delete(ctx, *(*godigest.Digest)(unsafe.Pointer(&shaToDelete))); err == nil {
					panic("odd")
				}
				dig, err := reference.WithDigest(justpath, *(*godigest.Digest)(unsafe.Pointer(&shaToDelete)))
				if err != nil {
					panic(err)
				}
				mfstURLStr, err := ub.BuildManifestURL(dig)
				if err != nil {
					panic(err)
				}
				// fmt.Printf("%T %#v", mfstURLStr, mfstURLStr)
				url, err := url.Parse(mfstURLStr)
				if err != nil {
					panic(err)
				}
				justdig, err := godigest.Parse(filepath.Base(url.Path))
				if err != nil {
					panic(err)
				}
				url.Path = filepath.Join(filepath.Dir(url.Path), justdig.Encoded())
				req, err := http.NewRequest(http.MethodDelete, url.String(), nil)
				if err != nil {
					panic(err)
				}
				req.Header.Add("Accept", digestToDelete.MediaType)
				resp, err := client.Do(req)
				if err != nil {
					panic(err)
				}
				defer resp.Body.Close()
				if distributionclient.SuccessStatus(resp.StatusCode) {
					b, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						panic(err)
					}
					deleteResponse := struct {
						Errors []string `json:"errors"`
					}{}
					if err := json.Unmarshal(b, &deleteResponse); err != nil {
						panic(err)
					}
					fmt.Printf("%#v, %#v", string(b), deleteResponse.Errors)
				}
			}
			return nil
		},
	}
}

func DockerfileCommand() *cli.Command {
	return &cli.Command{
		Name: "dockerfile",
		Action: func(c *cli.Context) error {
			templ := `FROM gcr.io/api-project-421333809285/gat/{{ .Image }}
COPY ./{{ .Ipynb }} .
CMD [ "start.sh", "jupyter", "nbconvert", "--to", "notebook", "--execute", "{{ .Ipynb }}" ]
`
			t := template.Must(template.New("Dockerfile").Parse(templ))
			type Dockerfile struct {
				Image string
				Ipynb string
			}
			required := requiredHack(c, "dockerfile", []string{"image", "ipynb"})
			var buf bytes.Buffer
			if err := t.Execute(&buf, Dockerfile{
				Image: filepath.Base(required[0]),
				Ipynb: required[1],
			}); err != nil {
				panic(err)
			}
			repo := c.Context.Value(repoKey).(*git.Repository)
			worktree := c.Context.Value(worktreeKey).(*git.Worktree)
			var pwd string
			if worktree != nil {
				pwd = worktree.Path()
			} else {
				pwd = filepath.Dir(repo.Path())
			}
			dockerfile := "Dockerfile." + strings.TrimSuffix(required[1], filepath.Ext(required[1]))
			ioutil.WriteFile(filepath.Join(pwd, dockerfile), buf.Bytes(), 0644)
			return nil
		},
	}
}

func singleIpynb(c *cli.Context) string {
	repo := c.Context.Value(repoKey).(*git.Repository)
	worktree := c.Context.Value(worktreeKey).(*git.Worktree)
	var pwd string
	if worktree != nil {
		pwd = worktree.Path()
	} else {
		pwd = filepath.Dir(repo.Path())
	}
	files, err := filepath.Glob(filepath.Join(pwd, "*.ipynb"))
	if err != nil {
		panic(err)
	}
	ipynb := c.String("ipynb")
	if len(ipynb) == 0 {
		if len(files) != 1 {
			cli.ShowCommandHelpAndExit(c, c.Command.Name, -1)
		} else {
			ipynb = files[0]
		}
	} else if _, err := os.Stat(ipynb); os.IsNotExist(err) {
		if filepath.Ext(ipynb) != ".ipynb" {
			ipynb += ".ipynb"
			if _, err := os.Stat(ipynb); os.IsNotExist(err) {
				panic(fmt.Sprintf("%s not found\n", ipynb))
			}
		} else {
			panic(fmt.Sprintf("%s not found\n", ipynb))
		}
	}
	return filepath.Base(ipynb)
}

func BuildCommand() *cli.Command {
	return &cli.Command{
		Name:  "build",
		Flags: buildFlags(),
		Action: func(c *cli.Context) error {
			repo := c.Context.Value(repoKey).(*git.Repository)
			worktree := c.Context.Value(worktreeKey).(*git.Worktree)
			ipynb := singleIpynb(c)
			dockerfile := "Dockerfile." + strings.TrimSuffix(ipynb, filepath.Ext(ipynb))
			repo1 := c.Context.Value(repo1Key).(*git.Repository)
			config := c.Context.Value(configKey).(*git.Config)
			project := c.String("project")
			zone := c.String("zone")
			region := c.String("region")
			if _, err := os.Stat(dockerfile); os.IsNotExist(err) {
				if err := c.App.RunContext(NewContext(repo, repo1, worktree, config),
					[]string{c.App.Name, "--project", project, "--zone", zone, "--region", region, "dockerfile", "base-notebook", ipynb}); err != nil {
					panic(err)
				}
				panic(fmt.Sprintf("Must first edit %s\n", dockerfile))
			}
			if err := buildImage(project, constructTag(c), dockerfile); err != nil {
				panic(err)
			}
			return nil
		},
	}
}

func PushCommand() *cli.Command {
	return &cli.Command{
		Name:  "push",
		Flags: pushFlags(),
		Action: func(c *cli.Context) error {
			repo := c.Context.Value(repoKey).(*git.Repository)
			repo1 := c.Context.Value(repo1Key).(*git.Repository)
			worktree := c.Context.Value(worktreeKey).(*git.Worktree)
			config := c.Context.Value(configKey).(*git.Config)
			project := c.String("project")
			zone := c.String("zone")
			region := c.String("region")
			ipynb := singleIpynb(c)
			if err := c.App.RunContext(NewContext(repo, repo1, worktree, config),
				[]string{c.App.Name, "--project", project, "--zone", zone, "--region", region, "build", "--ipynb", ipynb}); err != nil {
				panic(err)
			}
			var oldDigest, newDigest v1.Hash
			if oldImage := getImage(project, constructTag(c)); oldImage != nil {
				oldDigest, _ = oldImage.Digest()
			}
			if err := pushImage(project, constructTag(c)); err != nil {
				panic(err)
			}
			if newImage := getImage(project, constructTag(c)); newImage != nil {
				newDigest, _ = newImage.Digest()
			}
			if len(oldDigest.Hex) > 0 && oldDigest.String() != newDigest.String() {
				if err := deleteImage(project, constructTag(c), oldDigest); err != nil {
					panic(err)
				}
			}
			return nil
		},
	}
}

func RunRemoteCommand() *cli.Command {
	return &cli.Command{
		Name:  "run-remote",
		Flags: runRemoteFlags(),
		Action: func(c *cli.Context) error {
			repo := c.Context.Value(repoKey).(*git.Repository)
			repo1 := c.Context.Value(repo1Key).(*git.Repository)
			worktree := c.Context.Value(worktreeKey).(*git.Worktree)
			config := c.Context.Value(configKey).(*git.Config)
			project := c.String("project")
			zone := c.String("zone")
			region := c.String("region")
			ipynb := singleIpynb(c)
			if err := c.App.RunContext(NewContext(repo, repo1, worktree, config),
				[]string{c.App.Name, "--project", project, "--zone", zone, "--region", region, "push", "--ipynb", ipynb}); err != nil {
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

			bytes, newline_escaped, err := escapeCredentials()
			user_data := UserData(c, project, constructTag(c), fmt.Sprintf("gs://%s", gatId(c)), filepath.Base(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")), newline_escaped, "/var/tmp")
			var diskSizeGb int64
			tag := constructTag(c)
			if images, err := getImages(project, tag); err != nil || len(images) == 0 {
				if len(images) == 0 {
					panic(fmt.Sprintf("Image tagged %s not found", tag))
				} else {
					panic(err)
				}
			} else {
				diskSizeGb = 6 + images[0].Size/units.GiB
				if diskSizeGb < 8 {
					diskSizeGb = 8
				}
			}
			shutdown_script := Shutdown(c, project, constructTag(c), gatId(c), filepath.Base(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")), newline_escaped, "/var/tmp")
			var serviceAccount ServiceAccount
			json.Unmarshal(bytes, &serviceAccount)
			prefix := "https://www.googleapis.com/compute/v1/projects/" + project
			instance := &compute.Instance{
				Name:        gatId(c),
				Description: "gat compute instance",
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
							// SourceImage: "projects/cos-cloud/global/images/family/cos-beta",
							SourceImage: "projects/api-project-421333809285/global/images/cos-81-12871-96-202004291659",
							DiskSizeGb:  diskSizeGb,
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

func massageEscapes(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `\"`, `""`), `\\`, `\`)
}

func RunLocalCommand() *cli.Command {
	return &cli.Command{
		Name:  "run-local",
		Flags: runLocalFlags(),
		Action: func(c *cli.Context) error {
			repo := c.Context.Value(repoKey).(*git.Repository)
			repo1 := c.Context.Value(repo1Key).(*git.Repository)
			worktree := c.Context.Value(worktreeKey).(*git.Worktree)
			config := c.Context.Value(configKey).(*git.Config)
			project := c.String("project")
			zone := c.String("zone")
			region := c.String("region")
			ipynb := singleIpynb(c)
			if err := c.App.RunContext(NewContext(repo, repo1, worktree, config),
				[]string{c.App.Name, "--project", project, "--zone", zone, "--region", region, "build", "--ipynb", ipynb}); err != nil {
				panic(err)
			}
			config1, err := repo1.Config()
			if err != nil {
				panic(err)
			}
			config1.SetString("remote.origin.fetch", "refs/heads/*:refs/heads/*")
			config1.SetString("gat.last_project", project)

			_, newline_escaped, err := escapeCredentials()
			var pwd string
			if worktree != nil {
				pwd = worktree.Path()
			} else {
				pwd = filepath.Dir(repo.Path())
			}
			scommands := DockerCommands(c, project, constructTag(c), pwd, os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"), newline_escaped, filepath.Dir(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")))

			commands := strings.Split(scommands, "\n")
			type runError struct {
				error
				output []byte
			}
			defer func() {
				if r := recover(); r != nil {
					for _, str := range commands {
						if strings.Contains(str, "docker rm") {
							r := csv.NewReader(strings.NewReader(massageEscapes(str)))
							r.Comma = ' '
							if sw, err := r.Read(); err == nil {
								exec.Command(sw[0], sw[1:]...).Run()
							}
						}
					}
					if runerr, ok := r.(runError); ok {
						fmt.Printf("%s\n", string(runerr.output))
					}
					panic(r)
				}
			}()
			for _, str := range commands {
				if len(str) == 0 {
					continue
				}
				r := csv.NewReader(strings.NewReader(massageEscapes(str)))
				r.Comma = ' '
				if sw, err := r.Read(); err != nil {
					panic(err)
				} else {
					cmd := exec.Command(sw[0], sw[1:]...)
					if output, err := cmd.CombinedOutput(); err != nil {
						panic(runError{err, output})
					}
				}
			}
			return nil
		},
	}
}

func getImages(project string, tag string) ([]types.ImageSummary, error) {
	ensureApplicationDefaultCredentials()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}
	return cli.ImageList(context.Background(),
		types.ImageListOptions{Filters: filters.NewArgs(filters.Arg("reference", tag))})
}

func pushImage(project string, tag string) error {
	if images, err := getImages(project, tag); err != nil || len(images) == 0 {
		if len(images) == 0 {
			panic(fmt.Sprintf("Image tagged %s not found", tag))
		} else {
			panic(err)
		}
	}
	target := filepath.Join("gcr.io", project, tag)
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}
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

func buildImage(project string, tag string, dockerfile string) error {
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
	buildResponse, err := cli.ImageBuild(context.Background(), buildContext, types.ImageBuildOptions{
		Tags:        []string{tag},
		Remove:      true,
		ForceRemove: true,
		Dockerfile:  dockerfile,
		Labels: map[string]string{
			"gat": tag,
		},
	})
	if err != nil {
		panic(err)
	}
	defer buildResponse.Body.Close()
	termFd, isTerm := term.GetFdInfo(os.Stderr)
	if err := jsonmessage.DisplayJSONMessagesStream(buildResponse.Body, os.Stderr, termFd, isTerm, nil); err != nil {
		panic(err)
	}

	// cleanup old
	labelFilters := filters.NewArgs()
	labelFilters.Add("dangling", "true")
	labelFilters.Add("label", "gat="+tag)
	if _, err = cli.ImagesPrune(context.Background(), labelFilters); err != nil {
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
			region := c.String("region")
			return c.App.RunContext(NewContext(repo, repo1, worktree, config),
				[]string{c.App.Name, "--project", project, "--zone", zone, "--region", region, "edit", branchName})
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

func sendgridFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:     "api-key",
			Required: true,
			Usage:    "Set up mailer",
		},
	}
}

func runRemoteFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:  "noshutdown",
			Usage: "do not execute shutdown.service",
		},
		&cli.StringFlag{
			Name:  "ipynb",
			Usage: "ipynb file to build",
		},
	}
}

func runLocalFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "ipynb",
			Usage: "ipynb file to build",
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

func pushFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "ipynb",
			Usage: "ipynb file to build",
		},
	}
}

func buildFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "ipynb",
			Usage: "ipynb file to build",
		},
	}
}

func waitOp(s *cloudfunctions.Service, name string, sec int, ms int) (bool, *cloudfunctions.Status) {
	// https://gist.github.com/ngauthier/d6e6f80ce977bedca601
	timeout := time.After(time.Duration(sec) * time.Second)
	tick := time.Tick(time.Duration(ms) * time.Millisecond)
	service := cloudfunctions.NewOperationsService(s)
	for {
		select {
		case <-timeout:
			return false, nil
		case <-tick:
			if op, err := service.Get(name).Do(); err != nil {
				panic(err)
			} else if op.Done {
				return true, op.Error
			}
		}
	}
}
