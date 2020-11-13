package main

import (
	"fmt"
	"os"

	commands "github.com/dickmao/gat/commands"
	"github.com/spf13/viper"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

//go:generate go run cos_gpu_installer_generate/cos_gpu_installer_generate.go

func newApp() *cli.App {
	app := cli.NewApp()

	// source-gat will force-populate these if user doesn't specify
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:     "project",
			Required: true,
			Aliases:  []string{"p"},
			Usage:    "GCE project",
		},
		&cli.StringFlag{
			Name:     "zone",
			Required: true,
			Aliases:  []string{"z"},
			Usage:    "GCE zone",
		},
		&cli.StringFlag{
			Name:     "region",
			Required: true,
			Aliases:  []string{"r"},
			Usage:    "AWS or GCE region, e.g., us-east-2, us-central1",
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

func main() {
	// r, _ := git.PlainOpenWithOptions(".", &git.PlainOpenOptions{DetectDotGit: true})
	// headRef, _ := r.Head()
	// ref := plumbing.NewHashReference("refs/heads/my-branch", headRef.Hash())
	// r.Storer.SetReference(ref)
	logrus.SetLevel(logrus.InfoLevel)
	logrus.SetOutput(os.Stdout)

	viper.SetConfigName("config")
	viper.SetConfigType("toml")
	if _, ok := os.LookupEnv("XDG_CONFIG_HOME"); ok {
		viper.AddConfigPath("$XDG_CONFIG_HOME/.config/gat")
	} else {
		viper.AddConfigPath("$HOME/.config/gat")
	}
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			if err := viper.SafeWriteConfig(); err != nil {
				panic(err)
			}
		} else {
			panic(err)
		}
	}
	if err := newApp().Run(os.Args); err != nil {
		panic(err)
	}
}
