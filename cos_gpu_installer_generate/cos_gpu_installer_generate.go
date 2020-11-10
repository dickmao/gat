package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	git "github.com/dickmao/git2go/v32"
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

// https://stackoverflow.com/a/29500100/5132008
func main() {
	out, _ := os.Create("cos_gpu_installer/cos_gpu_installer.go")
	out.Write([]byte("package cos_gpu_installer\n\nconst (\n"))
	git_dir, _ := git.Discover(".", true, nil)
	repo, _ := git.OpenRepository(git_dir)
	defer repo.Free()
	commit, _ := headCommit(repo)
	defer commit.Free()
	tree, _ := commit.Tree()
	tree.Walk(func(root string, entry *git.TreeEntry) int {
		if filepath.Clean(root) == "cos_gpu_installer/scripts" {
			out.Write([]byte(strings.Title(strings.ReplaceAll(strings.TrimSuffix(entry.Name, filepath.Ext(entry.Name)), "-", "_")) + " = `"))
			f, _ := os.Open(filepath.Join(root, entry.Name))
			io.Copy(out, f)
			out.Write([]byte("`\n"))
		}
		return 0
	})
	out.Write([]byte(")\n"))
}
