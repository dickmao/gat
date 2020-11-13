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
	"os/user"
	"path/filepath"
	"regexp"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"cloud.google.com/go/logging/logadmin"
	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/dickmao/gat/cos_gpu_installer"
	"github.com/dickmao/gat/version"
	git "github.com/dickmao/git2go/v32"
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
	"github.com/spf13/viper"

	godigest "github.com/opencontainers/go-digest"
	"github.com/urfave/cli/v2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudfunctions/v1"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/googleapi"
	giam "google.golang.org/api/iam/v1"
	"google.golang.org/api/logging/v2"
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
const MasterWorktree string = "master"

var (
	resourceManagerService     *cloudresourcemanager.Service
	computeService             *compute.Service
	containerService           *container.Service
	storageClient              *storage.Client
	myAuthn                    *authn.Basic
	awsSession                 *session.Session
	awsSts                     *sts.STS
	awsEcr                     *ecr.ECR
	awsS3                      *s3.S3
	awsEC2                     *ec2.EC2
	resourceManagerServiceOnce sync.Once
	computeServiceOnce         sync.Once
	containerServiceOnce       sync.Once
	storageClientOnce          sync.Once
	myAuthnOnce                sync.Once
	awsSessionOnce             sync.Once
	awsStsOnce                 sync.Once
	awsEcrOnce                 sync.Once
	awsS3Once                  sync.Once
	awsEC2Once                 sync.Once
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

func gatId(c *cli.Context, prefix string) string {
	return prefix + "-" + strings.ReplaceAll(constructTag(c), ":", "-")
}

func initGat(c *cli.Context) error {
	var config *git.Config
	if config_loc, err := git.ConfigFindGlobal(); err != nil {
		if err.(*git.GitError).Code == git.ErrNotFound {
			if nc, err := git.NewConfig(); err != nil {
				return err
			} else {
				config = nc
			}
		} else {
			return err
		}
	} else if oc, err := git.OpenOndisk(config_loc); err != nil {
		return err
	} else {
		config = oc
	}
	repo, err := getRepo(".", config, true)
	if err != nil {
		return err
	}
	if _, err := repo.NewWorktreeFromSubrepository(); err == nil {
		repo, err = getRepo(filepath.Dir(filepath.Clean(repo.Workdir())), config, true)
		if err != nil {
			return err
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
		return err
	}
	for _, r := range []*git.Repository{repo, repo1} {
		if err = r.AddIgnoreRule(strings.Join([]string{".gat", "run-local", "run-remote"}, "\n")); err != nil {
			return err
		}
	}
	if err = os.MkdirAll(filepath.Join(repo1.Path(), "objects/pack"),
		os.ModePerm); err != nil {
		return err
	}
	config1, err := repo1.Config()
	if err != nil {
		return err
	}
	config1.SetString("remote.origin.fetch", "refs/heads/*:refs/heads/*")
	return nil
}

func ensureContext(c *cli.Context) error {
	var config *git.Config
	if config_loc, err := git.ConfigFindGlobal(); err != nil {
		return err
	} else if c, err := git.OpenOndisk(config_loc); err != nil {
		return err
	} else {
		config = c
	}
	repo, err := getRepo(".", config, false)
	if err != nil {
		return err
	}
	worktree, err := repo.NewWorktreeFromSubrepository()
	if err == nil {
		repo, err = getRepo(filepath.Dir(filepath.Clean(repo.Workdir())), config, false)
		if err != nil {
			return err
		}
	}
	gat_path := filepath.Join(repo.Workdir(), ".gat")
	git_dir1, err := git.Discover(gat_path, true, nil)
	var repo1 *git.Repository
	if err != nil {
		return err
	} else if repo1, err = git.OpenRepository(filepath.Clean(git_dir1)); err != nil {
		return err
	}
	for _, r := range []*git.Repository{repo, repo1} {
		if err = r.AddIgnoreRule(strings.Join([]string{".gat", "run-local", "run-remote"}, "\n")); err != nil {
			return err
		}
	}
	if err = os.MkdirAll(filepath.Join(repo1.Path(), "objects/pack"),
		os.ModePerm); err != nil {
		return err
	}
	config1, err := repo1.Config()
	if err != nil {
		return err
	}
	config1.SetString("remote.origin.fetch", "refs/heads/*:refs/heads/*")
	c.Context = NewContext(repo, repo1, worktree, config)
	return nil
}

func ensureBucketGce(c *cli.Context) error {
	project := c.String("project")
	bucket := getClientStorage().Bucket(gatId(c, project))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	if err := bucket.Create(ctx, project, &storage.BucketAttrs{}); err != nil {
		if err.(*googleapi.Error).Code == 409 {
			return nil
		}
		return err
	}
	return nil
}

func ensureBucketAws(c *cli.Context, region string, bucket string) error {
	result, err := getAwsS3(region).ListBuckets(&s3.ListBucketsInput{})
	for _, v := range result.Buckets {
		if *v.Name == bucket {
			return nil
		}
	}
	_, err = getAwsS3(region).CreateBucket(&s3.CreateBucketInput{
		Bucket: aws.String(bucket),
		CreateBucketConfiguration: &s3.CreateBucketConfiguration{
			LocationConstraint: aws.String(region),
		},
	})
	return err
}

func getBucketNameAws(c *cli.Context, region string) string {
	identity, err := getAwsSts(region).GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		panic(err)
	}
	return gatId(c, *identity.Account)
}

func mountBucketAws(c *cli.Context, region string, pwd string) error {
	bucket := getBucketNameAws(c, region)
	if err := ensureBucketAws(c, region, bucket); err != nil {
		return err
	}
	mountpoint := filepath.Join(pwd, "run-remote")
	type runError struct {
		error
		output []byte
	}
	defer func() {
		if r := recover(); r != nil {
			exec.Command("fusermount", "-u", mountpoint).Run()
			if runerr, ok := r.(runError); ok {
				fmt.Printf("%s\n", string(runerr.output))
			}
			panic(r)
		}
	}()
	// `results` subdir can be mounted even if it doesn't exist yet.
	if err := exec.Command("grep", "-qs", mountpoint+" ", "/proc/mounts").Run(); err != nil {
		if err := os.MkdirAll(mountpoint, 0755); err != nil {
			panic(err)
		}
		current, _ := user.Current()
		creds := credentials.NewChainCredentials(
			[]credentials.Provider{
				&credentials.SharedCredentialsProvider{},
				&credentials.EnvProvider{},
			})
		credValue, err := creds.Get()
		if err != nil {
			panic(err)
		}
		args := []string{
			// s3fs v1.82 cannot read ~/.aws/credentials
			fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", credValue.AccessKeyID),
			fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", credValue.SecretAccessKey),
			"s3fs",
			mountpoint,
			"-o",
			fmt.Sprintf("url=https://s3.%s.amazonaws.com", region),
			"-o",
			fmt.Sprintf("bucket=%s", bucket),
			"-o",
			fmt.Sprintf("uid=%s", current.Uid),
			"-o",
			fmt.Sprintf("umask=077"),
			"-o",
			fmt.Sprintf("gid=%s", current.Gid),
		}
		if strings.Contains(bucket, ".") {
			args = append(args, "-o", "use_path_request_style")
		}
		cmd := exec.Command("env", args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			panic(runError{err, output})
		}
	}
	return nil
}

func mountBucketGce(c *cli.Context, pwd string) error {
	if err := ensureBucketGce(c); err != nil {
		return err
	}
	bucket := gatId(c, c.String("project"))
	mountpoint := filepath.Join(pwd, "run-remote")
	type runError struct {
		error
		output []byte
	}
	defer func() {
		if r := recover(); r != nil {
			exec.Command("fusermount", "-u", mountpoint).Run()
			if runerr, ok := r.(runError); ok {
				fmt.Printf("%s\n", string(runerr.output))
			}
			panic(r)
		}
	}()
	// `results` subdir can be mounted even if it doesn't exist yet.
	if err := exec.Command("grep", "-qs", mountpoint+" ", "/proc/mounts").Run(); err != nil {
		if err := os.MkdirAll(mountpoint, 0755); err != nil {
			panic(err)
		}
		cmd := exec.Command("gcsfuse", "--implicit-dirs", "--file-mode", "444", bucket, mountpoint)
		if output, err := cmd.CombinedOutput(); err != nil {
			panic(runError{err, output})
		}
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

func ensureCredentialsGce() {
	if _, ok := os.LookupEnv("GOOGLE_APPLICATION_CREDENTIALS"); !ok {
		panic("Set GOOGLE_APPLICATION_CREDENTIALS to service_account.json")
	}
}

func getClientStorage() *storage.Client {
	storageClientOnce.Do(func() {
		ensureCredentialsGce()
		var err error
		if storageClient, err = storage.NewClient(context.Background()); err != nil {
			panic(err)
		}
	})
	return storageClient
}

func getAwsEC2(region string) *ec2.EC2 {
	awsEC2Once.Do(func() {
		awsEC2 = ec2.New(getAwsSession(region))
	})
	return awsEC2
}

func getAwsS3(region string) *s3.S3 {
	awsS3Once.Do(func() {
		awsS3 = s3.New(getAwsSession(region))
	})
	return awsS3
}

func getAwsSession(region string) *session.Session {
	awsSessionOnce.Do(func() {
		awsSession = session.Must(session.NewSessionWithOptions(session.Options{
			Config: aws.Config{
				Region: aws.String(region),
			},
			SharedConfigState: session.SharedConfigEnable,
		}))
	})
	return awsSession
}

func getAwsSts(region string) *sts.STS {
	awsStsOnce.Do(func() {
		awsSts = sts.New(getAwsSession(region))
	})
	return awsSts
}

func getAwsEcr(region string) *ecr.ECR {
	awsEcrOnce.Do(func() {
		awsEcr = ecr.New(getAwsSession(region))
	})
	return awsEcr
}

func getMyAuthn() *authn.Basic {
	myAuthnOnce.Do(func() {
		ensureCredentialsGce()
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
		ensureCredentialsGce()
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
		ensureCredentialsGce()
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
		ensureCredentialsGce()
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
		if git.IsErrorClass(err, git.ErrClassReference) {
			fmt.Fprintf(os.Stderr, "branchReference: needs at least one commit\n")
		}
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

func ensureRepoAws(region string, tag string) {
	ecrRepoName, _ := func() (string, string) {
		x := strings.Split(tag, ":")
		return x[0], x[1]
	}()
	svc := getAwsEcr(region)
	if _, err := svc.DescribeRepositories(&ecr.DescribeRepositoriesInput{
		RepositoryNames: []*string{
			aws.String(ecrRepoName),
		},
	}); err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() != ecr.ErrCodeRepositoryNotFoundException {
				panic(aerr)
			} else if _, err := svc.CreateRepository(&ecr.CreateRepositoryInput{
				RepositoryName: aws.String(ecrRepoName),
			}); err != nil {
				panic(err)
			}
		} else {
			panic(err)
		}
	}
}

func getImageAws(region string, tag string) (string, error) {
	ensureRepoAws(region, tag)
	ecrRepoName, ecrRepoTag := func() (string, string) {
		x := strings.Split(tag, ":")
		return x[0], x[1]
	}()
	svc := getAwsEcr(region)
	if extant, err := svc.BatchGetImage(&ecr.BatchGetImageInput{
		ImageIds: []*ecr.ImageIdentifier{
			{
				ImageTag: aws.String(ecrRepoTag),
			},
		},
		RepositoryName: aws.String(ecrRepoName),
	}); err != nil {
		return "", err
	} else if len(extant.Images) > 0 {
		return *extant.Images[0].ImageId.ImageDigest, nil
	}
	return "", errors.New(fmt.Sprintf("No extant image %s in %s", ecrRepoTag, ecrRepoName))
}

func getImageGce(project string, tag string) v1.Image {
	refTag, err := name.ParseReference(filepath.Join("gcr.io", project, tag))
	if err != nil {
		panic(err)
	}
	img, _ := remote.Image(refTag, remote.WithAuth(getMyAuthn()))
	return img
}

func deleteImageGce(project string, tag string, digest v1.Hash) error {
	refDig, err := name.ParseReference(filepath.Join("gcr.io", project, tag[:strings.IndexByte(tag, ':')]+"@"+digest.String()))
	if err != nil {
		panic(err)
	}
	if err = remote.Delete(refDig, remote.WithAuth(getMyAuthn())); err != nil {
		panic(err)
	}
	return nil
}

func deleteImageAws(region string, tag string, digest string) error {
	ecrRepoName, _ := func() (string, string) {
		x := strings.Split(tag, ":")
		return x[0], x[1]
	}()
	svc := getAwsEcr(region)
	if result, err := svc.BatchDeleteImage(&ecr.BatchDeleteImageInput{
		ImageIds: []*ecr.ImageIdentifier{
			{
				ImageDigest: aws.String(digest),
			},
		},
		RepositoryName: aws.String(ecrRepoName),
	}); err != nil {
		return err
	} else if len(result.Failures) > 0 {
		return errors.New(fmt.Sprintf("BatchDeleteImage %s: %s (%s)", result.Failures[0].ImageId.ImageDigest, result.Failures[0].FailureReason, result.Failures[0].FailureCode))
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

func escapeCredentials(filename string) ([]byte, string, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return bytes, "", err
	}
	quoted_escaped := strconv.Quote(string(bytes))
	modifier_escaped := strings.Replace(quoted_escaped[1:len(quoted_escaped)-1], "%", "%%", -1)
	newline_escaped := strings.Replace(modifier_escaped, "\\\\n", "\\\\\\\\n", -1)
	return bytes, newline_escaped, nil
}

func processEnvs(envs []string) []string {
	for i, env := range envs {
		valued, _ := regexp.Match(`=`, []byte(env))
		if !valued {
			envs[i] = fmt.Sprintf("%s=%s", env, os.Getenv(env))
		}
	}
	return envs
}

func printLogAws(qFirst bool, term *bool, lastInsertId *string, until string, nextunit string) func(page *cloudwatchlogs.FilterLogEventsOutput, lastPage bool) bool {
	return func(page *cloudwatchlogs.FilterLogEventsOutput, lastPage bool) bool {
		myPayload := struct {
			Message          string `json:"message"`
			Host             string `json:"host"`
			SourceType       string `json:"source_type"`
			Priority         string `json:"PRIORITY"`
			SyslogFacility   string `json:"SYSLOG_FACILITY"`
			SyslogIdentifier string `json:"SYSLOG_IDENTIFIER"`
			SystemdUnit      string `json:"_SYSTEMD_UNIT"`
		}{}
		f := bufio.NewWriter(os.Stdout)
		defer f.Flush()
		var newLastInsertId string
		for _, event := range page.Events {
			if !qFirst && len(newLastInsertId) == 0 && len(*lastInsertId) > 0 {
				if *event.EventId == *lastInsertId {
					newLastInsertId = *lastInsertId
				}
				continue
			}
			newLastInsertId = *event.EventId
			if err := json.Unmarshal([]byte(*event.Message), &myPayload); err != nil {
				panic(err)
			}
			if !*term && len(until) > 0 {
				*term = strings.Contains(myPayload.Message, until)
			}
			if !*term && len(nextunit) > 0 {
				*term = myPayload.SystemdUnit == nextunit
			}
			f.WriteString(fmt.Sprintf("%s\n", myPayload.Message))
		}
		*lastInsertId = newLastInsertId
		return lastPage
	}
}

func printLogGce(qFirst bool, term *bool, lastInsertId *string) func(r *logging.ListLogEntriesResponse) error {
	return func(r *logging.ListLogEntriesResponse) error {
		myPayload := struct {
			Message          string `json:"MESSAGE"`
			Priority         string `json:"PRIORITY"`
			SyslogFacility   string `json:"SYSLOG_FACILITY"`
			SyslogIdentifier string `json:"SYSLOG_IDENTIFIER"`
		}{}
		f := bufio.NewWriter(os.Stdout)
		defer f.Flush()
		var newLastInsertId string
		for _, entry := range r.Entries {
			if !qFirst && len(newLastInsertId) == 0 && len(*lastInsertId) > 0 {
				if entry.InsertId == *lastInsertId {
					newLastInsertId = *lastInsertId
				}
				continue
			}
			newLastInsertId = entry.InsertId
			if err := json.Unmarshal(entry.JsonPayload, &myPayload); err != nil {
				return err
			}
			if !*term {
				*term = strings.HasPrefix(myPayload.Message, "gat1.service: Consumed")
			}
			f.WriteString(fmt.Sprintf("%s\n", myPayload.Message))
		}
		*lastInsertId = newLastInsertId
		return nil
	}
}

func recordTargetId(lastInstanceId *uint64) func(ol *compute.OperationList) error {
	return func(ol *compute.OperationList) error {
		for _, op := range ol.Items {
			*lastInstanceId = op.TargetId
		}
		return nil
	}
}

func ensureJupyterSecurityGroup(c *cli.Context) (*string, error) {
	const jupyterSecurityGroupName string = "gat-jupyter"
	region := c.String("region")
	svc := getAwsEC2(region)
	var jupyterSecurityGroupId *string
	if result, err := svc.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		GroupNames: []*string{aws.String(jupyterSecurityGroupName)},
	}); err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "InvalidGroup.NotFound":
				if result, err := svc.CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
					Description: aws.String(jupyterSecurityGroupName),
					GroupName:   aws.String(jupyterSecurityGroupName),
				}); err != nil {
					return nil, err
				} else if _, err := svc.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
					FromPort:   aws.Int64(8888),
					ToPort:     aws.Int64(8888),
					GroupId:    result.GroupId,
					IpProtocol: aws.String("tcp"),
					CidrIp:     aws.String("0.0.0.0/0"),
				}); err != nil {
					svc.DeleteSecurityGroup(&ec2.DeleteSecurityGroupInput{
						GroupId: result.GroupId,
					})
					return nil, err
				} else if _, err := svc.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
					FromPort:   aws.Int64(22),
					ToPort:     aws.Int64(22),
					GroupId:    result.GroupId,
					IpProtocol: aws.String("tcp"),
					CidrIp:     aws.String("0.0.0.0/0"),
				}); err != nil {
					svc.DeleteSecurityGroup(&ec2.DeleteSecurityGroupInput{
						GroupId: result.GroupId,
					})
					return nil, err
				} else {
					jupyterSecurityGroupId = result.GroupId
				}
			default:
				return nil, err
			}
		}
	} else {
		jupyterSecurityGroupId = result.SecurityGroups[0].GroupId
	}
	return jupyterSecurityGroupId, nil
}

func ensureInstanceProfile() (*iam.InstanceProfile, error) {
	const instanceProfileName string = "gat"
	const instanceProfileRoleName string = "gatServiceRole"
	const policyDocument string = `{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole"
    }]
}
`
	var instanceProfile *iam.InstanceProfile
	var instanceProfileRole *iam.Role
	svcIam := iam.New(session.New())
	if _, err := svcIam.GetRole(&iam.GetRoleInput{
		RoleName: aws.String(instanceProfileRoleName),
	}); err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				if result, err := svcIam.CreateRole(&iam.CreateRoleInput{
					AssumeRolePolicyDocument: aws.String(policyDocument),
					RoleName:                 aws.String(instanceProfileRoleName),
				}); err != nil {
					return nil, err
				} else if _, err = svcIam.AttachRolePolicy(&iam.AttachRolePolicyInput{
					PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonEC2FullAccess"),
					RoleName:  aws.String(instanceProfileRoleName),
				}); err != nil {
					svcIam.DeleteRole(&iam.DeleteRoleInput{
						RoleName: aws.String(instanceProfileRoleName),
					})
					return nil, err
				} else if _, err = svcIam.AttachRolePolicy(&iam.AttachRolePolicyInput{
					PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonS3FullAccess"),
					RoleName:  aws.String(instanceProfileRoleName),
				}); err != nil {
					svcIam.DeleteRole(&iam.DeleteRoleInput{
						RoleName: aws.String(instanceProfileRoleName),
					})
					return nil, err
				} else if _, err = svcIam.AttachRolePolicy(&iam.AttachRolePolicyInput{
					PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"),
					RoleName:  aws.String(instanceProfileRoleName),
				}); err != nil {
					svcIam.DeleteRole(&iam.DeleteRoleInput{
						RoleName: aws.String(instanceProfileRoleName),
					})
					return nil, err
				} else if _, err = svcIam.AttachRolePolicy(&iam.AttachRolePolicyInput{
					PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonElasticFileSystemFullAccess"),
					RoleName:  aws.String(instanceProfileRoleName),
				}); err != nil {
					svcIam.DeleteRole(&iam.DeleteRoleInput{
						RoleName: aws.String(instanceProfileRoleName),
					})
					return nil, err
				} else if _, err = svcIam.AttachRolePolicy(&iam.AttachRolePolicyInput{
					PolicyArn: aws.String("arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"),
					RoleName:  aws.String(instanceProfileRoleName),
				}); err != nil {
					svcIam.DeleteRole(&iam.DeleteRoleInput{
						RoleName: aws.String(instanceProfileRoleName),
					})
					return nil, err
				} else if _, err = svcIam.AttachRolePolicy(&iam.AttachRolePolicyInput{
					PolicyArn: aws.String("arn:aws:iam::aws:policy/AWSLambdaFullAccess"),
					RoleName:  aws.String(instanceProfileRoleName),
				}); err != nil {
					svcIam.DeleteRole(&iam.DeleteRoleInput{
						RoleName: aws.String(instanceProfileRoleName),
					})
					return nil, err
				} else if _, err = svcIam.AttachRolePolicy(&iam.AttachRolePolicyInput{
					PolicyArn: aws.String("arn:aws:iam::aws:policy/CloudWatchEventsFullAccess"),
					RoleName:  aws.String(instanceProfileRoleName),
				}); err != nil {
					svcIam.DeleteRole(&iam.DeleteRoleInput{
						RoleName: aws.String(instanceProfileRoleName),
					})
					return nil, err
				} else if _, err = svcIam.AttachRolePolicy(&iam.AttachRolePolicyInput{
					PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonEventBridgeFullAccess"),
					RoleName:  aws.String(instanceProfileRoleName),
				}); err != nil {
					svcIam.DeleteRole(&iam.DeleteRoleInput{
						RoleName: aws.String(instanceProfileRoleName),
					})
					return nil, err
				} else if _, err = svcIam.AttachRolePolicy(&iam.AttachRolePolicyInput{
					PolicyArn: aws.String("arn:aws:iam::aws:policy/IAMFullAccess"),
					RoleName:  aws.String(instanceProfileRoleName),
				}); err != nil {
					svcIam.DeleteRole(&iam.DeleteRoleInput{
						RoleName: aws.String(instanceProfileRoleName),
					})
					return nil, err
				} else {
					instanceProfileRole = result.Role
				}
			default:
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	if result, err := svcIam.GetInstanceProfile(&iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String(instanceProfileName),
	}); err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				if result, err := svcIam.CreateInstanceProfile(&iam.CreateInstanceProfileInput{
					InstanceProfileName: aws.String(instanceProfileName),
				}); err != nil {
					if aerr, ok := err.(awserr.Error); ok {
						return nil, aerr
					} else {
						return nil, err
					}
				} else {
					instanceProfile = result.InstanceProfile
				}
			default:
				return nil, aerr
			}
		} else {
			return nil, err
		}
	} else {
		instanceProfile = result.InstanceProfile
	}

	if instanceProfileRole != nil {
		if _, err := svcIam.RemoveRoleFromInstanceProfile(&iam.RemoveRoleFromInstanceProfileInput{
			InstanceProfileName: instanceProfile.InstanceProfileName,
			RoleName:            instanceProfileRole.RoleName,
		}); err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case iam.ErrCodeNoSuchEntityException:
					// fine i suppose
				default:
					return nil, aerr
				}
			} else {
				return nil, err
			}
		}
		if _, err := svcIam.AddRoleToInstanceProfile(&iam.AddRoleToInstanceProfileInput{
			InstanceProfileName: instanceProfile.InstanceProfileName,
			RoleName:            instanceProfileRole.RoleName,
		}); err != nil {
			return nil, err
		} else if out, err := svcIam.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{
			RoleName: instanceProfileRole.RoleName,
		}); err != nil || len(out.AttachedPolicies) < 5 {
			return nil, err
		}
	}
	return instanceProfile, nil
}

func TestCommand() *cli.Command {
	return &cli.Command{
		Name:  "test",
		Flags: testFlags(),
		Action: func(c *cli.Context) error {
			if err := ensureContext(c); err != nil {
				panic(err)
			}
			region := c.String("region")
			svc := getAwsEC2(region)
			result, _ := svc.DescribeVpcs(
				&ec2.DescribeVpcsInput{
					Filters: []*ec2.Filter{
						&ec2.Filter{
							Name: aws.String("isDefault"),
							Values: []*string{
								aws.String("true"),
							},
						},
					},
				},
			)
			fmt.Println(*result.Vpcs[0].VpcId)
			sgid, err := ensureJupyterSecurityGroup(c)
			if err != nil {
				panic(err)
			}
			fmt.Println(*sgid)
			return nil
		},
	}
}

func isAwsRegion(region string) bool {
	matched, _ := regexp.Match(`-\d$`, []byte(region))
	return matched
}

func RunRemoteCommand() *cli.Command {
	return &cli.Command{
		Name:  "run-remote",
		Flags: runRemoteFlags(),
		Action: func(c *cli.Context) error {
			if err := ensureContext(c); err != nil {
				panic(err)
			}
			if isAwsRegion(c.String("region")) {
				return runRemoteAws(c)
			}
			return runRemoteGce(c)
		},
	}
}

func repositoryUriGce(c *cli.Context) string {
	project := c.String("project")
	tag := constructTag(c)
	return filepath.Join("gcr.io", project, tag)
}

func repositoryUriAws(c *cli.Context) string {
	region := c.String("region")
	tag := constructTag(c)
	identity, _ := getAwsSts(region).GetCallerIdentity(&sts.GetCallerIdentityInput{})
	server := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", *identity.Account, region)
	return filepath.Join(server, tag)
}

func runRemoteAws(c *cli.Context) error {
	repo := c.Context.Value(repoKey).(*git.Repository)
	repo1 := c.Context.Value(repo1Key).(*git.Repository)
	worktree := c.Context.Value(worktreeKey).(*git.Worktree)
	project := c.String("project")
	zone := c.String("zone")
	region := c.String("region")
	keyname := c.String("keyname")
	if len(keyname) <= 0 {
		if viper.IsSet("keyname") {
			keyname = viper.GetString("keyname")
		} else {
			panic(fmt.Sprintf("Requires keyname in --keyname or config."))
		}
	} else {
		if !viper.IsSet("keyname") {
			viper.Set("keyname", keyname)
			viper.WriteConfig()
		}
	}
	infile := inputDockerfile(c)
	if err := c.App.Run(
		[]string{c.App.Name, "--project", project, "--zone", zone, "--region", region, "push", "--dockerfile", infile}); err != nil {
		panic(err)
	}
	config1, err := repo1.Config()
	if err != nil {
		panic(err)
	}
	if err := config1.SetString("remote.origin.fetch", "refs/heads/*:refs/heads/*"); err != nil {
		panic(err)
	}

	var pwd string
	if worktree != nil {
		pwd = worktree.Path()
	} else {
		pwd = filepath.Dir(filepath.Clean(repo.Path()))
	}
	if err := mountBucketAws(c, region, pwd); err != nil {
		panic(err)
	}

	machine := c.String("machine")
	var gpus string
	if len(machine) == 0 {
		machine = "t2.micro"
	} else if ok, _ := regexp.Match(`^(g|p)`, []byte(machine)); ok {
		gpus = " --gpus all"
	}

	envs := processEnvs(c.StringSlice("env"))
	tag := constructTag(c)
	user_data := UserDataAws(c, tag, repositoryUriAws(c), fmt.Sprintf("s3://%s", getBucketNameAws(c, region)), gpus, region, envs)
	diskSizeGb := c.Int64("disksizegb")
	if diskSizeGb <= 0 {
		if images, err := getImages(tag); err != nil || len(images) == 0 {
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
	}
	profile, err := ensureInstanceProfile()
	if err != nil || profile == nil {
		panic(err)
	}
	sgid, err := ensureJupyterSecurityGroup(c)
	if err != nil {
		panic(err)
	}
	var reservation *ec2.Reservation
	svc := getAwsEC2(region)
	for i, retries := 0, 12; i < retries+1; i++ {
		if i >= retries {
			panic("Retries exceeded")
		}
		reservation, err = svc.RunInstances(&ec2.RunInstancesInput{
			IamInstanceProfile: &ec2.IamInstanceProfileSpecification{
				Arn: profile.Arn,
			},
			InstanceMarketOptions: &ec2.InstanceMarketOptionsRequest{
				MarketType:  aws.String(ec2.MarketTypeSpot),
				SpotOptions: &ec2.SpotMarketOptions{},
			},
			ImageId:      aws.String("ami-02b8e6d3c495eb290"), // packer.json
			InstanceType: aws.String(machine),
			MinCount:     aws.Int64(1),
			MaxCount:     aws.Int64(1),
			KeyName:      aws.String(keyname),
			UserData:     &user_data,
			BlockDeviceMappings: []*ec2.BlockDeviceMapping{
				{
					DeviceName: aws.String("/dev/sdh"),
					Ebs: &ec2.EbsBlockDevice{
						VolumeSize: aws.Int64(diskSizeGb),
					},
				},
			},
			SecurityGroupIds: []*string{
				sgid,
			},
		})
		if err != nil {
			if reqErr, ok := err.(awserr.RequestFailure); ok {
				if reqErr.StatusCode() == 400 {
					awsErr, _ := err.(awserr.Error)
					fmt.Println("Waiting... ", awsErr.Message())
					time.Sleep(10000 * time.Millisecond)
					continue
				}
				panic(reqErr)
			}
			panic(err)
		} else {
			break
		}
	}
	if _, errtag := svc.CreateTags(&ec2.CreateTagsInput{
		Resources: []*string{reservation.Instances[0].InstanceId},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String("Name"),
				Value: aws.String(tag),
			},
		},
	}); errtag != nil {
		panic(errtag)
	}
	fmt.Println("Created instance", *reservation.Instances[0].InstanceId)

	for i, retries := 0, 12; i < retries+1; i++ {
		if i >= retries {
			panic("Retries exceeded")
		}
		if output, err := svc.DescribeInstances(&ec2.DescribeInstancesInput{
			InstanceIds: []*string{
				reservation.Instances[0].InstanceId,
			},
		}); err != nil {
			panic(err)
		} else {
			var state string
			if output.Reservations[0].Instances[0].State == nil {
				state = "null"
			} else {
				state = *output.Reservations[0].Instances[0].State.Name
			}
			if state != ec2.InstanceStateNamePending && state != "null" {
				fmt.Println(*output.Reservations[0].Instances[0].PublicIpAddress,
					*output.Reservations[0].Instances[0].PublicDnsName)
				break
			}
			fmt.Println("Instance state", state, "...")
			time.Sleep(10000 * time.Millisecond)
		}
	}

	return nil
}

func VersionCommand() *cli.Command {
	return &cli.Command{
		Name: "version",
		Action: func(c *cli.Context) error {
			fmt.Println(version.Version)
			return nil
		},
	}
}

func LogCommand() *cli.Command {
	return &cli.Command{
		Name:  "log",
		Flags: logFlags(),
		Action: func(c *cli.Context) error {
			if err := ensureContext(c); err != nil {
				panic(err)
			}
			if isAwsRegion(c.String("region")) {
				return logAws(c)
			}
			return logGce(c)
		},
	}
}

func logAws(c *cli.Context) error {
	region := c.String("region")
	svc := cloudwatchlogs.New(getAwsSession(region))
	tag := constructTag(c)
	after := time.Unix(c.Int64("after"), 0)
	var term bool
	var lastInsertId string
	for qFirst := true; ; qFirst = false {
		// I would use GetLogEventsPages with StartFromHead=true, but
		// OutputLogEvent does not have an EventId member
		if err := svc.FilterLogEventsPages(
			&cloudwatchlogs.FilterLogEventsInput{
				LogGroupName: aws.String(strings.ReplaceAll(tag, `:`, `-`)),
				StartTime:    aws.Int64(after.UnixNano() / int64(time.Millisecond)),
			},
			printLogAws(qFirst, &term, &lastInsertId, c.String("until"), c.String("nextunit"))); err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case cloudwatch.ErrCodeResourceNotFoundException:
				default:
					return aerr
				}
			} else {
				return err
			}
		}
		if !term && (c.Bool("follow") || len(c.String("until")) != 0 || len(c.String("nextunit")) != 0) {
			// delay between log entry and fluentd's
			// recording is ~5s so only looking after
			// `after` would miss entries in last
			// five seconds.
			after = time.Now().Add(-time.Minute)
			time.Sleep(1200 * time.Millisecond)
		} else {
			break
		}
	}
	return nil
}

func logGce(c *cli.Context) error {
	computeService, err := compute.NewService(context.Background(), option.WithScopes(compute.ComputeReadonlyScope))
	if err != nil {
		panic(err)
	}
	filter := []string{}
	filter = append(filter, fmt.Sprintf("(operationType = \"insert\")"))
	serviceAccountBytes, _, _ := escapeCredentials(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
	var serviceAccount ServiceAccount
	json.Unmarshal(serviceAccountBytes, &serviceAccount)
	filter = append(filter, fmt.Sprintf("(user = \"%s\")", serviceAccount.Client_email))
	project := c.String("project")
	zone := c.String("zone")
	var lastInstanceId uint64
	for follow := true; lastInstanceId == 0 && follow; follow = c.Bool("follow") {
		if err := compute.NewZoneOperationsService(computeService).List(project, zone).Filter(strings.Join(filter, " AND ")).Pages(context.Background(), recordTargetId(&lastInstanceId)); err != nil {
			panic(err)
		}
	}
	loggingService, err := logging.NewService(context.Background(), option.WithScopes(logging.LoggingReadScope))
	if err != nil {
		panic(err)
	}
	filter = []string{}
	filter = append(filter, fmt.Sprintf("logName = \"projects/%s/logs/gat\"", project))
	filter = append(filter, fmt.Sprintf("resource.labels.instance_id = \"%d\"", lastInstanceId))
	filter = append(filter, fmt.Sprintf("resource.type = \"gce_instance\""))
	freshness := c.String("freshness")
	if len(freshness) == 0 {
		freshness = "24h"
	}
	dur, err := time.ParseDuration(freshness)
	if err != nil {
		panic(err)
	} else if dur > 0 {
		dur = -dur
	}
	after := time.Now().Add(dur)
	if err != nil {
		panic(err)
	}
	var term bool
	var lastInsertId string
	for qFirst := true; ; qFirst = false {
		if err := logging.NewEntriesService(loggingService).List(&logging.ListLogEntriesRequest{
			Filter:        strings.Join(append(filter, fmt.Sprintf("timestamp >= \"%s\"", after.Format(time.RFC3339))), " AND "),
			ResourceNames: []string{fmt.Sprintf("projects/%s", project)},
		}).Pages(context.Background(), printLogGce(qFirst, &term, &lastInsertId)); err != nil {
			panic(err)
		}
		if !term && c.Bool("follow") {
			// delay between log entry and fluentd's
			// recording is ~5s so only looking after
			// `after` would miss entries in last
			// five seconds.
			after = time.Now().Add(-time.Minute)
			time.Sleep(1200 * time.Millisecond)
		} else {
			break
		}
	}
	return nil
}

func timezoneOf(region string) string {
	if strings.HasPrefix(region, "us-west") {
		return "US/Pacific"
	} else if strings.HasPrefix(region, "us-east") {
		return "US/Eastern"
	} else if strings.HasPrefix(region, "us-central") {
		return "US/Central"
	} else if strings.HasPrefix(region, "asia/southeast") {
		return "Asia/Singapore"
	} else if strings.HasPrefix(region, "asia/south") {
		return "Asia/Kolkata"
	} else if strings.HasPrefix(region, "asia") {
		return "Asia/Tokyo"
	} else if strings.HasPrefix(region, "europe") {
		return "MET"
	} else if strings.HasPrefix(region, "australia") {
		return "Australia/Sydney"
	} else if strings.HasPrefix(region, "australia") {
		return "Australia/Sydney"
	} else if strings.HasPrefix(region, "northamerica") {
		return "US/Eastern"
	} else if strings.HasPrefix(region, "southamerica") {
		return "Brazil/East"
	}
	return "GMT"
}

func SendgridCommand() *cli.Command {
	return &cli.Command{
		Name:  "sendgrid",
		Flags: sendgridFlags(),
		Action: func(c *cli.Context) error {
			if err := ensureContext(c); err != nil {
				panic(err)
			}
			project := c.String("project")
			topic := url.Values{}
			topic.Set("topic", "compute.googleapis.com/activity_log")
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
				} else if _, err = f.Write(PubSubSource(c, c.String("name"), c.String("address"), c.String("key"), timezoneOf(region))); err != nil {
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
			if err := ensureContext(c); err != nil {
				panic(err)
			}
			if err := ensureBucketGce(c); err != nil {
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
				url.Path = filepath.Join(filepath.Dir(filepath.Clean(url.Path)), justdig.Encoded())
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
	// input Dockerfile.main, output Dockerfile.main.gat
	return &cli.Command{
		Name: "dockerfile",
		Action: func(c *cli.Context) error {
			// input Dockerfile, output Dockerfile.gat
			if err := ensureContext(c); err != nil {
				panic(err)
			}
			infile := requiredHack(c, "dockerfile", []string{"Dockerfile"})[0]
			cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
			if err != nil {
				panic(err)
			}

			baseTag := "base/" + constructTag(c)
			imageId, err := buildBaseImage(cli, baseTag, infile)
			if err != nil {
				panic(err)
			}
			defer func() {
				if r := recover(); r != nil {
					cli.ImageRemove(context.Background(), imageId, types.ImageRemoveOptions{
						Force:         true,
						PruneChildren: true,
					})
					panic(r)
				}
			}()
			ioutil.WriteFile(fmt.Sprintf("%s.gat", infile), DockerfileSource(c, cli, imageId), 0644)
			return nil
		},
	}
}

func inputDockerfile(c *cli.Context) string {
	result := c.String("dockerfile")
	if len(result) == 0 {
		pwd, _ := os.Getwd()
		globs, err := filepath.Glob(filepath.Join(pwd, "Dockerfile*"))
		if err != nil {
			panic(err)
		}
		var cands []string
		for _, glob := range globs {
			if filepath.Ext(glob) != ".gat" {
				cands = append(cands, glob)
			}
		}
		if len(cands) != 1 {
			cli.ShowCommandHelpAndExit(c, c.Command.Name, -1)
		} else {
			result = cands[0]
		}
	}
	if _, err := os.Stat(result); os.IsNotExist(err) {
		panic(fmt.Sprintf("%s not found\n", result))
	}
	return filepath.Base(result)
}

func BuildCommand() *cli.Command {
	return &cli.Command{
		Name:  "build",
		Flags: buildFlags(),
		Action: func(c *cli.Context) error {
			if err := ensureContext(c); err != nil {
				panic(err)
			}
			project := c.String("project")
			zone := c.String("zone")
			region := c.String("region")
			infile := inputDockerfile(c)
			if err := c.App.Run([]string{c.App.Name, "--project", project, "--zone", zone, "--region", region, "dockerfile", infile}); err != nil {
				return err
			}
			if err := buildImage(project, constructTag(c), infile+".gat"); err != nil {
				return err
			}
			return nil
		},
	}
}

func pushAws(c *cli.Context) error {
	project := c.String("project")
	zone := c.String("zone")
	region := c.String("region")
	infile := inputDockerfile(c)
	if err := c.App.Run(
		[]string{c.App.Name, "--project", project, "--zone", zone, "--region", region, "build", "--dockerfile", infile}); err != nil {
		return err
	}

	tag := constructTag(c)
	oldDigest, _ := getImageAws(region, tag)

	svc := getAwsEcr(region)
	token, err := svc.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return err
	} else if len(token.AuthorizationData) <= 0 {
		return errors.New("commands: no authorization token returned")
	}
	passbytes, err := base64.StdEncoding.DecodeString(*token.AuthorizationData[0].AuthorizationToken)
	if err != nil {
		return err
	}

	username, password := func() (string, string) {
		x := strings.Split(string(passbytes), ":")
		return x[0], x[1]
	}()
	jsonBytes, _ := json.Marshal(types.AuthConfig{
		Username: username,
		Password: password,
	})

	if err := pushImage(repositoryUriAws(c), tag, jsonBytes); err != nil {
		return err
	}
	newDigest, _ := getImageAws(region, tag)
	if len(oldDigest) > 0 && oldDigest != newDigest {
		if err := deleteImageAws(region, tag, oldDigest); err != nil {
			return err
		}
	}
	return nil
}

func pushGce(c *cli.Context) error {
	project := c.String("project")
	zone := c.String("zone")
	region := c.String("region")
	infile := inputDockerfile(c)
	if err := c.App.Run(
		[]string{c.App.Name, "--project", project, "--zone", zone, "--region", region, "build", "--dockerfile", infile}); err != nil {
		return err
	}
	var oldDigest, newDigest v1.Hash
	if oldImage := getImageGce(project, constructTag(c)); oldImage != nil {
		oldDigest, _ = oldImage.Digest()
	}

	tag := constructTag(c)
	bytes, err := ioutil.ReadFile(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
	if err != nil {
		return err
	}
	jsonBytes, _ := json.Marshal(map[string]string{
		"username": "_json_key",
		"password": string(bytes),
	})
	if err := pushImage(filepath.Join("gcr.io", project, tag), tag, jsonBytes); err != nil {
		return err
	}
	if newImage := getImageGce(project, constructTag(c)); newImage != nil {
		newDigest, _ = newImage.Digest()
	}
	if len(oldDigest.Hex) > 0 && oldDigest.String() != newDigest.String() {
		if err := deleteImageGce(project, constructTag(c), oldDigest); err != nil {
			return err
		}
	}
	return nil
}

func PushCommand() *cli.Command {
	return &cli.Command{
		Name:  "push",
		Flags: pushFlags(),
		Action: func(c *cli.Context) error {
			if err := ensureContext(c); err != nil {
				panic(err)
			}
			if isAwsRegion(c.String("region")) {
				return pushAws(c)
			}
			return pushGce(c)
		},
	}
}

func runRemoteGce(c *cli.Context) error {
	repo := c.Context.Value(repoKey).(*git.Repository)
	repo1 := c.Context.Value(repo1Key).(*git.Repository)
	worktree := c.Context.Value(worktreeKey).(*git.Worktree)
	project := c.String("project")
	zone := c.String("zone")
	region := c.String("region")
	infile := inputDockerfile(c)
	if err := c.App.Run(
		[]string{c.App.Name, "--project", project, "--zone", zone, "--region", region, "push", "--dockerfile", infile}); err != nil {
		panic(err)
	}
	config1, err := repo1.Config()
	if err != nil {
		panic(err)
	}
	if err := config1.SetString("remote.origin.fetch", "refs/heads/*:refs/heads/*"); err != nil {
		panic(err)
	}
	var pwd string
	if worktree != nil {
		pwd = worktree.Path()
	} else {
		pwd = filepath.Dir(filepath.Clean(repo.Path()))
	}
	if err := mountBucketGce(c, pwd); err != nil {
		panic(err)
	}

	envs := processEnvs(c.StringSlice("env"))
	bytes, newline_escaped, err := escapeCredentials(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
	tag := constructTag(c)
	user_data := UserDataGce(c, tag, repositoryUriGce(c), fmt.Sprintf("gs://%s", gatId(c, project)), newline_escaped, envs)
	diskSizeGb := c.Int64("disksizegb")
	if diskSizeGb <= 0 {
		if images, err := getImages(tag); err != nil || len(images) == 0 {
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
	}
	shutdown_script := Shutdown(c, tag)
	var serviceAccount ServiceAccount
	json.Unmarshal(bytes, &serviceAccount)
	prefix := "https://www.googleapis.com/compute/v1/projects/" + project
	machine := c.String("machine")
	if len(machine) == 0 {
		machine = "e2-standard-2"
	}
	gpuCount := c.Int64("gpus")
	acceleratorConfigs := []*compute.AcceleratorConfig{}
	if gpuCount > 0 {
		gpuType := c.String("gpu")
		if len(gpuType) == 0 {
			gpuType = "nvidia-tesla-t4"
		}
		acceleratorConfigs = append(acceleratorConfigs, &compute.AcceleratorConfig{
			AcceleratorCount: gpuCount,
			AcceleratorType:  prefix + "/zones/" + zone + "/acceleratorTypes/" + gpuType,
		})
	}

	gpu_installer_env := cos_gpu_installer.Gpu_installer_env
	run_cuda_test := cos_gpu_installer.Run_cuda_test
	run_installer := cos_gpu_installer.Run_installer
	instance := &compute.Instance{
		Name:        gatId(c, project),
		Description: "gat compute instance",
		MachineType: prefix + "/zones/" + zone + "/machineTypes/" + machine,
		Metadata: &compute.Metadata{
			Items: []*compute.MetadataItems{
				{
					Key:   "user-data",
					Value: &user_data,
				},
				{
					Key:   "cos-gpu-installer-env",
					Value: &gpu_installer_env,
				},
				{
					Key:   "run-cuda-test-script",
					Value: &run_cuda_test,
				},
				{
					Key:   "run-installer-script",
					Value: &run_installer,
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
					SourceImage: "projects/api-project-421333809285/global/images/cos-81-12871-96-202006181203",
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
					giam.CloudPlatformScope,
				},
			},
		},
		GuestAccelerators: acceleratorConfigs,
	}
	instancesService := compute.NewInstancesService(getService())
	if op, err := instancesService.Insert(project, zone, instance).Context(context.Background()).Do(); err != nil {
		panic(err)
	} else {
		fmt.Println(op.Name)
	}
	return nil
}

func massageEscapes(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(s, `\"`, `""`), `\\`, `\`), `$$`, `$`)
}

func executeShellWords(s string) ([]byte, error) {
	r := csv.NewReader(strings.NewReader(massageEscapes(s)))
	r.Comma = ' '
	if sw, err := r.Read(); err == nil {
		return exec.Command(sw[0], sw[1:]...).CombinedOutput()
	} else {
		return nil, err
	}
}

func RunLocalCommand() *cli.Command {
	return &cli.Command{
		Name:  "run-local",
		Flags: runLocalFlags(),
		Action: func(c *cli.Context) error {
			if err := ensureContext(c); err != nil {
				panic(err)
			}
			repo := c.Context.Value(repoKey).(*git.Repository)
			repo1 := c.Context.Value(repo1Key).(*git.Repository)
			worktree := c.Context.Value(worktreeKey).(*git.Worktree)
			project := c.String("project")
			zone := c.String("zone")
			region := c.String("region")
			infile := inputDockerfile(c)
			if err := c.App.Run(
				[]string{c.App.Name, "--project", project, "--zone", zone, "--region", region, "build", "--dockerfile", infile}); err != nil {
				panic(err)
			}
			config1, err := repo1.Config()
			if err != nil {
				panic(err)
			}
			config1.SetString("remote.origin.fetch", "refs/heads/*:refs/heads/*")
			config1.SetString("gat.last_project", project)

			var pwd string
			if worktree != nil {
				pwd = worktree.Path()
			} else {
				pwd = filepath.Dir(filepath.Clean(repo.Path()))
			}

			envs := processEnvs(c.StringSlice("env"))
			scommands := DockerCommands(c, constructTag(c), pwd, envs)
			commands := strings.Split(scommands, "\n")
			type runError struct {
				error
				command string
				output  []byte
			}
			// executeShellWords(`gcloud config set pass_credentials_to_gsutil false`)
			defer func() {
				if r := recover(); r != nil {
					for _, str := range commands {
						if strings.Contains(str, "docker rm") {
							executeShellWords(str)
						}
					}

					if runerr, ok := r.(runError); ok {
						fmt.Printf("%s: %s\n", runerr.command, string(runerr.output))
					}
					panic(r)
				}
			}()

			for _, str := range commands {
				if len(str) == 0 {
					continue
				}
				if output, err := executeShellWords(str); err != nil {
					panic(runError{err, str, output})
				} else if c.Bool("debug") {
					fmt.Printf("%s\n", string(output))
				}
			}
			return nil
		},
	}
}

func getImages(tag string) ([]types.ImageSummary, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}
	return cli.ImageList(context.Background(),
		types.ImageListOptions{Filters: filters.NewArgs(filters.Arg("reference", tag))})
}

func pushImage(target string, tag string, jsonBytes []byte) error {
	if images, err := getImages(tag); err != nil || len(images) == 0 {
		if len(images) == 0 {
			return errors.New(fmt.Sprintf("Image tagged %s not found", tag))
		} else {
			return err
		}
	}
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	if err := cli.ImageTag(context.Background(), tag, target); err != nil {
		return err
	}

	if _, err := cli.ImagesPrune(context.Background(),
		filters.NewArgs(filters.Arg("label", "gat="+tag))); err != nil {
		return err
	}

	pushBody, err := cli.ImagePush(context.Background(), target, types.ImagePushOptions{
		RegistryAuth: base64.StdEncoding.EncodeToString(jsonBytes),
	})
	if err != nil {
		return err
	}
	defer pushBody.Close()
	termFd, isTerm := term.GetFdInfo(os.Stderr)
	return jsonmessage.DisplayJSONMessagesStream(pushBody, os.Stderr, termFd, isTerm, nil)
}

func buildBaseImage(cli *client.Client, baseTag string, infile string) (string, error) {
	buildContext, err := archive.TarWithOptions(".", &archive.TarOptions{})
	if err != nil {
		panic(err)
	}
	defer buildContext.Close()
	// cleanup old
	defer func() {
		labelFilters := filters.NewArgs()
		labelFilters.Add("dangling", "true")
		labelFilters.Add("label", "gat="+baseTag)
		cli.ImagesPrune(context.Background(), labelFilters)
	}()

	fmt.Fprintf(os.Stderr, "Building image... "+baseTag+"\n")
	buildResponse, err := cli.ImageBuild(context.Background(), buildContext, types.ImageBuildOptions{
		Tags:        []string{baseTag},
		Remove:      true,
		ForceRemove: true,
		Dockerfile:  infile,
		Labels: map[string]string{
			"gat": baseTag,
		},
	})
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(os.Stderr, "Building image... "+baseTag+" done\n")
	defer buildResponse.Body.Close()
	devnull, _ := os.Open(os.DevNull)
	devnull = os.Stderr
	termFd, isTerm := term.GetFdInfo(devnull)
	if err := jsonmessage.DisplayJSONMessagesStream(buildResponse.Body, devnull, termFd, isTerm, nil); err != nil {
		panic(err)
	}
	// no aux found in DisplayJSONMessagesStream, and don't want to parse.
	images, err := getImages(baseTag)
	if err != nil || len(images) == 0 {
		if len(images) == 0 {
			panic(fmt.Sprintf("Image tagged %s not found", baseTag))
		} else {
			panic(err)
		}
	}
	return images[0].ID, nil
}

func buildImage(project string, tag string, outfile string) error {
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
		Dockerfile:  outfile,
		Labels: map[string]string{
			"gat": tag,
		},
	})
	if err != nil {
		panic(err)
	}
	defer buildResponse.Body.Close()
	defer func() {
		// cleanup old
		labelFilters := filters.NewArgs()
		labelFilters.Add("dangling", "true")
		labelFilters.Add("label", "gat="+tag)
		cli.ImagesPrune(context.Background(), labelFilters)
	}()

	termFd, isTerm := term.GetFdInfo(os.Stderr)
	if err := jsonmessage.DisplayJSONMessagesStream(buildResponse.Body, os.Stderr, termFd, isTerm, nil); err != nil {
		panic(err)
	}

	return nil
}

func promptWorktree(prompt string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s", prompt)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return scanner.Text(), scanner.Err()
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
		branchName, err = promptWorktree("New worktree: ")
		if err != nil {
			if stash_oid != nil {
				repo.Stashes.Pop(0, opts)
			}
			panic(err)
		}
	}
	if branchName == MasterWorktree {
		if stash_oid != nil {
			repo.Stashes.Pop(0, opts)
		}
		panic(fmt.Sprintf("Extant branch \"%v\"", branchName))
	}
	if old_branch, err := repo1.LookupBranch(branchName, git.BranchLocal); err == nil {
		defer old_branch.Free()
		if stash_oid != nil {
			if err := repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
		}
		panic(fmt.Sprintf("Extant branch \"%v\" %v", branchName, stash_oid))
	}
	commit, err := headCommit(repo)
	if err != nil {
		if stash_oid != nil {
			if err := repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
		}
		panic(err)
	}
	defer commit.Free()
	to_delete, err := repo.CreateBranch(branchName, commit, false)
	if err != nil {
		if stash_oid != nil {
			if err := repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
		}
		panic(err)
	}
	defer to_delete.Free()

	if stash_oid != nil {
		repo.SetHead(to_delete.Reference.Name())
		if err = repo.Stashes.Apply(0, opts); err != nil {
			if err := repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
			panic(err)
		}
		idx, err := repo.Index()
		if err != nil {
			if err := repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
			panic(err)
		}
		defer idx.Free()
		// stage
		if err = idx.UpdateAll([]string{"."}, nil); err != nil {
			if err := repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
			panic(err)
		}
		if err = idx.AddAll([]string{"."}, git.IndexAddDefault, nil); err != nil {
			if err := repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
			panic(err)
		}
		// for i := uint(0); i < idx.EntryCount(); i += 1 {
		// 	entry, err := idx.EntryByIndex(i)
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// 	fmt.Fprintf(os.Stderr, "%s\n", entry.Path)
		// }
		treeID, _ := idx.WriteTree()
		tree, err := repo.LookupTree(treeID)
		if err != nil {
			if err := repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
			panic(err)
		}
		// commit
		currentTip, err := repo.LookupCommit(to_delete.Target())
		if _, err := repo.CreateCommit("HEAD", sig, sig, fmt.Sprintf("gat create %s", branchName), tree, currentTip); err != nil {
			if err := repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
			panic(err)
		}
		// restore master
		repo.SetHead(to_return.Name())
		if err = repo.CheckoutHead(&git.CheckoutOpts{Strategy: git.CheckoutRemoveUntracked}); err != nil {
			if err := repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
			panic(err)
		}
		if err = repo.ResetToCommit(commit, git.ResetHard, &git.CheckoutOpts{Strategy: git.CheckoutForce}); err != nil {
			if err := repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
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
		branchName, err = promptWorktree("New worktree: ")
		if err != nil {
			panic(err)
		}
	}
	if branchName == MasterWorktree {
		if stash_oid != nil {
			if err := worktree.Repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
		}
		panic(fmt.Sprintf("Extant branch \"%v\"", branchName))
	}
	if old_branch, err := repo1.LookupBranch(branchName, git.BranchLocal); err == nil {
		defer old_branch.Free()
		if stash_oid != nil {
			if err := worktree.Repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
		}
		panic(fmt.Sprintf("Extant branch \"%v\"", branchName))
	}

	// i need the commit of worktree
	commit, err := headCommit(worktree.Repo)
	if err != nil {
		if stash_oid != nil {
			if err := worktree.Repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
		}
		panic(err)
	}
	defer commit.Free()

	new_branch, err := repo1.CreateBranch(branchName, commit, false)
	if err != nil {
		if stash_oid != nil {
			if err := worktree.Repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
		}
		panic(err)
	}
	defer new_branch.Free()

	options, err := git.NewWorktreeAddOptions(1, 0, new_branch.Reference)
	if err != nil {
		if stash_oid != nil {
			if err := worktree.Repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
		}
		panic(err)
	}
	repo1_worktree, err := repo1.AddWorktree(branchName, filepath.Join(repo1.Path(), new_branch.Reference.Shorthand()), options)
	if err != nil {
		if stash_oid != nil {
			if err := worktree.Repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
		}
		panic(err)
	}
	defer repo1_worktree.Free()

	if stash_oid != nil {
		repo2, err := git.OpenRepository(filepath.Clean(repo1_worktree.Path()))
		if err != nil {
			if err := worktree.Repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
			panic(err)
		}
		defer repo2.Free()

		new_worktree, err := repo2.NewWorktreeFromSubrepository()
		if err != nil {
			if err := worktree.Repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
			panic(err)
		}
		defer new_worktree.Free()

		if err = new_worktree.Repo.Stashes.Apply(0, opts); err != nil {
			if err := worktree.Repo.Stashes.Pop(0, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stash pop: %s\n", err)
			}
			panic(err)
		}
		if err := worktree.Repo.Stashes.Pop(0, opts); err != nil {
			panic(err)
		}

		// stage
		idx, err := new_worktree.Repo.Index()
		if err != nil {
			panic(err)
		}
		defer idx.Free()
		if err = idx.UpdateAll([]string{"."}, nil); err != nil {
			panic(err)
		}
		if err = idx.AddAll([]string{"."}, git.IndexAddDefault, nil); err != nil {
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
			if err := ensureContext(c); err != nil {
				if giterr, ok := err.(*git.GitError); ok {
					if giterr.Code == git.ErrNotFound {
						if err := initGat(c); err != nil {
							panic(err)
						} else if err := ensureContext(c); err != nil {
							panic(err)
						}
					}
				} else {
					panic(err)
				}
			}
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

			project := c.String("project")
			zone := c.String("zone")
			region := c.String("region")
			return c.App.Run(
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
			if err := ensureContext(c); err != nil {
				panic(err)
			}
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

func getRepo(path string, config *git.Config, create bool) (*git.Repository, error) {
	var (
		repo   *git.Repository
		reterr error
	)
	parent_dir, _ := filepath.Abs(filepath.Join(path, ".."))
	git_dir, err := git.Discover(path, true, []string{parent_dir})
	if err != nil {
		if create && err.(*git.GitError).Code == git.ErrNotFound {
			repo, reterr = git.InitRepository(path, false)
		} else {
			return nil, err
		}
	} else {
		if filepath.Base(filepath.Clean(git_dir)) == ".gat" {
			git_dir, err = git.Discover(filepath.Dir(filepath.Clean(git_dir)), true, nil)
			if err != nil {
				return nil, err
			}
		}
		repo, reterr = git.OpenRepository(filepath.Clean(git_dir))
	}

	if create && reterr == nil {
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
					return nil, err
				} else if tree, err := repo.LookupTree(treeID); err != nil {
					return nil, err
				} else {
					if err := idx.Write(); err != nil {
						return nil, err
					}
					if _, err := repo.CreateCommit("HEAD", sig, sig, fmt.Sprintf("gat create %s", MasterWorktree), tree); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	return repo, reterr
}

func MasterCommand() *cli.Command {
	return &cli.Command{
		Name:  "master",
		Flags: masterFlags(),
		Action: func(c *cli.Context) error {
			if err := ensureContext(c); err != nil {
				panic(err)
			}
			repo := c.Context.Value(repoKey).(*git.Repository)
			return cli.NewExitError(fmt.Sprintf("cd %s", filepath.Clean(repo.Workdir())), 7)
		},
	}
}

func EditCommand() *cli.Command {
	return &cli.Command{
		Name:  "edit",
		Flags: editFlags(),
		Action: func(c *cli.Context) error {
			if err := ensureContext(c); err != nil {
				panic(err)
			}
			repo1 := c.Context.Value(repo1Key).(*git.Repository)
			worktreeName := c.Args().Get(0)
			if worktreeName == "" {
				var err error
				if worktreeName, err = promptWorktree("Worktree: "); err != nil {
					panic(err)
				}
			}
			if worktreeName == MasterWorktree {
				project := c.String("project")
				zone := c.String("zone")
				region := c.String("region")
				return c.App.Run(
					[]string{c.App.Name, "--project", project, "--zone", zone, "--region", region, "master"})
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

func masterFlags() []cli.Flag {
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
			Name:     "name",
			Required: true,
			Usage:    "Sendgrid 'From' name",
		},
		&cli.StringFlag{
			Name:     "address",
			Required: true,
			Usage:    "Sendgrid 'From' email address",
		},
		&cli.StringFlag{
			Name:     "key",
			Required: true,
			Usage:    "Sendgrid API key",
		},
	}
}

func runRemoteFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:  "noshutdown",
			Usage: "Do not execute shutdown.service",
		},
		&cli.Int64Flag{
			Name:  "disksizegb",
			Usage: "Attached disk size in GiB",
		},
		&cli.Int64Flag{
			Name:  "gpus",
			Usage: "Add this number of gpus",
		},
		&cli.StringFlag{
			Name:  "dockerfile",
			Usage: "Dockerfile file to build",
		},
		&cli.StringFlag{
			Name:  "gpu",
			Usage: "Gpu name from acceleratorTypes, e.g., nvidia-tesla-t4",
		},
		&cli.StringFlag{
			Name:  "machine",
			Usage: "Machine type",
		},
		&cli.StringFlag{
			Name:  "user",
			Usage: "Docker command line option --user",
		},
		&cli.StringFlag{
			Name:  "keyname",
			Usage: "AWS keypair name",
		},
		&cli.StringSliceFlag{
			Name:  "env",
			Usage: "Docker command line option --env, e.g., KAGGLE_USERNAME=kaggler",
		},
		&cli.StringFlag{
			Name:  "command",
			Usage: "Docker command (arguments to entrypoint)",
		},
	}
}

func runLocalFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:  "debug",
			Usage: "Show outputs of docker commands",
		},
		&cli.StringFlag{
			Name:  "dockerfile",
			Usage: "Dockerfile file to build",
		},
		&cli.StringFlag{
			Name:  "user",
			Usage: "Docker command line option --user",
		},
		&cli.StringSliceFlag{
			Name:  "env",
			Usage: "Docker command line option --env, e.g., KAGGLE_USERNAME=kaggler",
		},
		&cli.StringFlag{
			Name:  "command",
			Usage: "Docker command (arguments to entrypoint)",
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
			Name:  "dockerfile",
			Usage: "Dockerfile file to build",
		},
	}
}

func buildFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "dockerfile",
			Usage: "Dockerfile file to build",
		},
	}
}

func logFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "freshness",
			Usage: "An expression parseable by time.ParseDuration",
		},
		&cli.BoolFlag{
			Name:    "follow",
			Aliases: []string{"f"},
			Usage:   "tail -f",
		},
		&cli.StringFlag{
			Name:  "until",
			Usage: "Follow until string value seen",
		},
		&cli.StringFlag{
			Name:  "nextunit",
			Usage: "Follow until _SYSTEMD_UNIT assumes this value",
		},
		&cli.Int64Flag{
			Name:  "after",
			Usage: "After this unixtime",
		},
	}
}

func testFlags() []cli.Flag {
	return []cli.Flag{}
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
