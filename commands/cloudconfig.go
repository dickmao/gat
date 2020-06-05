package commands

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/urfave/cli/v2"
)

type CloudConfig struct {
	Project                   string
	Tag                       string
	Bucket                    string
	ServiceAccountJson        string
	ServiceAccountJsonContent string
	Workdir                   string
	Gat0, Gat1                []string
}

var (
	gat0 = []string{
		`bash -c "docker run --entrypoint \"/bin/bash\" --name gat-sentinel-container {{ .Tag }} -c \"touch sentinel\""`,
		`bash -c "docker cp {{ .ServiceAccountJson }} gat-sentinel-container:$(docker inspect -f '{{"{{"}}json .Config.WorkingDir{{"}}"}}' gat-sentinel-container | sed 's/\"//g')/"`,
	}
	gat1 = []string{
		`bash -c "docker commit -c \"ENTRYPOINT $(docker inspect -f '{{"{{"}}json .Config.Entrypoint{{"}}"}}' {{ .Tag }})\" -c \"CMD $(docker inspect -f '{{"{{"}}json .Config.Cmd{{"}}"}}' {{ .Tag }})\" gat-sentinel-container gat-sentinel"`,
		`bash -c "docker commit gat-sentinel-container gat-sentinel"`,
		`docker rm gat-sentinel-container`,
		`bash -c "export ENTRYPOINT0=$(docker inspect -f '{{"{{"}}json .Config.Entrypoint{{"}}"}}' {{ .Tag }}) ; export CMD0=$(docker inspect -f '{{"{{"}}json .Config.Cmd{{"}}"}}' {{ .Tag }}) ; docker run --env GOOGLE_APPLICATION_CREDENTIALS=$(docker inspect -f '{{"{{"}}json .Config.WorkingDir{{"}}"}}' {{ .Tag }} | sed 's/\"//g')/$(basename {{ .ServiceAccountJson }}) --privileged --entrypoint \"$(if [ \"$ENTRYPOINT0\" = \"null\" ] ; then echo ; else echo $ENTRYPOINT0 ; fi)\" --name gat-run-container gat-sentinel $(if [ \"$CMD0\" = \"null\" ] ; then echo ; else echo $CMD0; fi)"`,
		`docker commit gat-run-container gat-run`,
		`docker rm gat-run-container`,
		`docker rmi gat-sentinel`,
		`bash -c "[ -d {{ .Bucket }} ] && mkdir -p {{ .Bucket }}/results || true"`,
		`bash -c "docker run --rm -v $([ -d {{ .Bucket }} ] && echo -n {{ .Bucket }} || echo -n $(pwd)):/hostpwd --entrypoint \"/bin/bash\" gat-run -c \"( [ \\$(realpath .) = '/' ] && export SYSDIRS='\\( -name boot -o -name dev -o -name etc -o -name home -o -name lib -o -name lib64 -o -name media -o -name mnt -o -name opt -o -name proc -o -name run -o -name sbin -o -name srv -o -name sys -o -name tmp -o -name usr -o -name var -o -name bin \\) -prune -o' ; for f in \\$(eval find . \\$SYSDIRS -not -path \\'*/.*\\' -type f -newer sentinel) ; do mkdir -p ./results/\\$(dirname \\$f) ; ln -s \\$(realpath \\$f) ./results/\\$f ; done ; ) && ( if [ -d ./results ]; then gsutil -m -o Credentials:gs_service_key_file=\\$(realpath ./\\$(basename {{ .ServiceAccountJson }})) rsync -r results $([ -d {{ .Bucket }} ] && echo -n /hostpwd || echo -n {{ .Bucket }})/results ; fi )\""`,
		`docker rmi gat-run`,
	}
)

// import "os"
// import "text/template"
// type localConfig struct {
//     Gat0[] string
//     Gat1[] string
//     Redouble string
// }
// t, _ := template.New("gomacro").Parse(`{{range .Gat1}}{{block "inner" .}}{{.}}{{end}}{{template "inner" .}}{{end}}`)
// t, _ := template.New("gomacro").Parse(`{{range .Gat1}}{{with .}}{{. | printf "%s\n" }}{{end}}{{ $.Redouble | printf "%s\n" }}{{end}}`)
// _ = t.Execute(os.Stdout, localConfig{ []string{"foo", "bar"}, []string{"baz {{ $.Redouble }}", "qux"}, "doubled" })

const templ string = `#cloud-config

users:
- default

write_files:
- path: /etc/systemd/system/gat0.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Write service account json

    [Service]
    Environment="HOME={{ .Workdir }}"
    WorkingDirectory={{ .Workdir }}
    Type=oneshot
    ExecStart=bash -c "echo $'{{ .ServiceAccountJsonContent }}' >$(basename {{ .ServiceAccountJson }}) && chmod 664 $(basename {{ .ServiceAccountJson }})"
    ExecStart=/usr/bin/docker-credential-gcr configure-docker
    ExecStart=/usr/bin/docker pull gcr.io/{{ .Project }}/{{ .Tag }}
    ExecStart=/usr/bin/docker tag gcr.io/{{ .Project }}/{{ .Tag }} {{ .Tag }}
{{ range .Gat0 }}{{ . | printf "    ExecStart=%s\n" }}{{ end }}

- path: /etc/systemd/system/gat1.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Run user experiment and upload results
    After=gat0.service

    [Service]
    Environment="HOME={{ .Workdir }}"
    WorkingDirectory={{ .Workdir }}
    Type=oneshot
{{ range .Gat1 }}{{ . | printf "    ExecStart=%s\n" }}{{ end }}

- path: /etc/systemd/system/shutdown.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Shutdown
    After=gat1.service

    [Service]
    Environment="HOME={{ .Workdir }}"
    WorkingDirectory={{ .Workdir }}
    Type=oneshot
    ExecStart=bash -c "curl -s --retry 2 -H \"Authorization: Bearer $(curl -s --retry 2 http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/$(cat {{ .Workdir }}/$(basename {{ .ServiceAccountJson }}) | jq -r -c '.client_email')/token -H 'Metadata-Flavor: Google' | jq -r -c '.access_token')\" -X DELETE https://compute.googleapis.com/compute/v1/$(curl -s --retry 2 http://metadata.google.internal/computeMetadata/v1/instance/zone -H 'Metadata-Flavor: Google')/instances/$(curl -s --retry 2 http://metadata.google.internal/computeMetadata/v1/instance/id -H 'Metadata-Flavor: Google')"

`

func DockerCommands(c *cli.Context, project string, tag string, bucket string, serviceAccountJson string, serviceAccountJsonContent string, workdir string) string {
	// double evaluation: could not get template {{block}} {{end}} to work.
	commands := `
{{ range .Gat0 }}{{ . | printf "%s\n" }}{{ end }}
{{ range .Gat1 }}{{ . | printf "%s\n" }}{{ end }}
`
	for i := 0; i < 2; i++ {
		t := template.Must(template.New("CloudConfig").Parse(commands))
		var buf bytes.Buffer
		if err := t.Execute(&buf, CloudConfig{
			Project:                   project,
			Tag:                       tag,
			Bucket:                    bucket,
			ServiceAccountJson:        serviceAccountJson,
			ServiceAccountJsonContent: serviceAccountJsonContent,
			Workdir:                   workdir,
			Gat0:                      gat0,
			Gat1:                      gat1,
		}); err != nil {
			panic(err)
		}
		commands = buf.String()
	}
	return commands
}

func UserData(c *cli.Context, project string, tag string, bucket string, serviceAccountJson string, serviceAccountJsonContent string, workdir string) string {
	runcmd := []string{"daemon-reload", "start gat0.service", "start gat1.service"}
	if !c.Bool("noshutdown") {
		runcmd = append(runcmd, "start shutdown.service")
	}
	userdata := templ
	userdata += "runcmd:\n"
	for _, value := range runcmd {
		userdata += fmt.Sprintf("- systemctl %s\n", value)
	}
	// double evaluation: could not get template {{block}} {{end}} to work.
	for i := 0; i < 2; i++ {
		t := template.Must(template.New("CloudConfig").Parse(userdata))
		var buf bytes.Buffer
		if err := t.Execute(&buf, CloudConfig{
			Project:                   project,
			Tag:                       tag,
			Bucket:                    bucket,
			ServiceAccountJson:        serviceAccountJson,
			ServiceAccountJsonContent: serviceAccountJsonContent,
			Workdir:                   workdir,
			Gat0:                      gat0,
			Gat1:                      gat1,
		}); err != nil {
			panic(err)
		}
		userdata = buf.String()
	}
	return userdata
}

func Shutdown(c *cli.Context, project string, tag string, bucket string, serviceAccountJson string, serviceAccountJsonContent string, workdir string) string {
	templ := `
#!/bin/bash

# REST API key deletion of {{ .Project }}{{ .Tag }}
`
	t := template.Must(template.New("cloudConfig").Parse(templ))
	var buf bytes.Buffer
	if err := t.Execute(&buf, CloudConfig{
		Project:                   project,
		Tag:                       tag,
		Bucket:                    bucket,
		ServiceAccountJson:        serviceAccountJson,
		ServiceAccountJsonContent: serviceAccountJsonContent,
		Workdir:                   workdir,
		Gat0:                      gat0,
		Gat1:                      gat1,
	}); err != nil {
		panic(err)
	}
	return buf.String()
}
