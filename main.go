package main

import (
	"math/rand"
	"os"
	"time"

	runCommand "github.com/dickmao/gat/commands"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func main() {
	// r, _ := git.PlainOpenWithOptions(".", &git.PlainOpenOptions{DetectDotGit: true})
	// headRef, _ := r.Head()
	// ref := plumbing.NewHashReference("refs/heads/my-branch", headRef.Hash())
	// r.Storer.SetReference(ref)

	logrus.SetLevel(logrus.InfoLevel)
	logrus.SetOutput(os.Stdout)

	rand.Seed(time.Now().UnixNano())

	app := cli.NewApp()
	app.Commands = []*cli.Command{
		runCommand.RunCommand(),
	}
	app.Run(os.Args)
}
