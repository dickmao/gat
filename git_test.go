package main

import (
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"testing"
	"time"

	git "github.com/dickmao/git2go/v31"
)

func checkFatal(t *testing.T, err error) {
	if err == nil {
		return
	}

	// The failure happens at wherever we were called, not here
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		t.Fatalf("Unable to get caller")
	}
	t.Fatalf("Fail at %v:%v; %v", file, line, err)
}

// snapshot of dickmao/git2go/git_test.go
func cleanupTestRepo(t *testing.T, r *git.Repository) {
	var err error
	if r.IsBare() {
		err = os.RemoveAll(r.Path())
	} else {
		err = os.RemoveAll(r.Workdir())
	}
	checkFatal(t, err)

	r.Free()
}

func createTestRepo(t *testing.T) *git.Repository {
	// figure out where we can create the test repo
	path, err := ioutil.TempDir("", "gat_test")
	checkFatal(t, err)
	repo, err := git.InitRepository(path, false)
	checkFatal(t, err)

	tmpfile := "README"
	err = ioutil.WriteFile(path+"/"+tmpfile, []byte("foo\n"), 0644)

	checkFatal(t, err)

	return repo
}

func createBareTestRepo(t *testing.T) *git.Repository {
	// figure out where we can create the test repo
	path, err := ioutil.TempDir("", "gat_test")
	checkFatal(t, err)
	repo, err := git.InitRepository(path, true)
	checkFatal(t, err)

	return repo
}

func seedTestRepo(t *testing.T, repo *git.Repository) (*git.Oid, *git.Oid) {
	loc, err := time.LoadLocation("Europe/Berlin")
	checkFatal(t, err)
	sig := &git.Signature{
		Name:  "Rand Om Hacker",
		Email: "random@hacker.com",
		When:  time.Date(2013, 03, 06, 14, 30, 0, 0, loc),
	}

	idx, err := repo.Index()
	checkFatal(t, err)
	err = idx.AddByPath("README")
	checkFatal(t, err)
	err = idx.Write()
	checkFatal(t, err)
	treeId, err := idx.WriteTree()
	checkFatal(t, err)

	message := "This is a commit\n"
	tree, err := repo.LookupTree(treeId)
	checkFatal(t, err)
	commitId, err := repo.CreateCommit("HEAD", sig, sig, message, tree)
	checkFatal(t, err)

	return commitId, treeId
}

func pathInRepo(repo *git.Repository, name string) string {
	return path.Join(path.Dir(path.Dir(repo.Path())), name)
}

func updateReadme(t *testing.T, repo *git.Repository, content string) (*git.Oid, *git.Oid) {
	loc, err := time.LoadLocation("Europe/Berlin")
	checkFatal(t, err)
	sig := &git.Signature{
		Name:  "Rand Om Hacker",
		Email: "random@hacker.com",
		When:  time.Date(2013, 03, 06, 14, 30, 0, 0, loc),
	}

	tmpfile := "README"
	err = ioutil.WriteFile(pathInRepo(repo, tmpfile), []byte(content), 0644)
	checkFatal(t, err)

	idx, err := repo.Index()
	checkFatal(t, err)
	err = idx.AddByPath("README")
	checkFatal(t, err)
	err = idx.Write()
	checkFatal(t, err)
	treeId, err := idx.WriteTree()
	checkFatal(t, err)

	currentBranch, err := repo.Head()
	checkFatal(t, err)
	currentTip, err := repo.LookupCommit(currentBranch.Target())
	checkFatal(t, err)

	message := "This is a commit\n"
	tree, err := repo.LookupTree(treeId)
	checkFatal(t, err)
	commitId, err := repo.CreateCommit("HEAD", sig, sig, message, tree, currentTip)
	checkFatal(t, err)

	return commitId, treeId
}

func TestOidZero(t *testing.T) {
	t.Parallel()
	var zeroId git.Oid

	if !zeroId.IsZero() {
		t.Error("Zero Oid is not zero")
	}
}

func TestEmptyOid(t *testing.T) {
	t.Parallel()
	_, err := git.NewOid("")
	if err == nil || !git.IsErrorCode(err, git.ErrGeneric) {
		t.Fatal("Should have returned invalid error")
	}
}
