package commands

import (
	"bytes"
	b64 "encoding/base64"
	"fmt"
	"strings"
	"text/template"

	"github.com/urfave/cli/v2"
)

type CloudConfig struct {
	Tag                       string
	Region                    string
	RepositoryUri             string
	Bucket                    string
	ServiceAccountJsonContent string
	ServiceAccountEnv         string
	Workdir                   string
	Envs                      []string
	User                      string
	Gpus                      string
	Gat0, Gat1, Gat2          []string
	Cmd                       string
}

var (
	gat0 = []string{
		`/bin/bash -c "[ -d {{ .Bucket }} ] && mkdir -p {{ .Bucket }}/run-caches || true"`,
		`/bin/bash -c "docker run --entrypoint \"/bin/bash\" --name gat-sentinel-container {{ .Tag }} -c \"touch sentinel\""`,
		`/bin/bash -c "[ -d {{ .Bucket }} ] || [ -f {{ .Workdir }}/credentials ] && docker cp {{ .Workdir }}/credentials gat-sentinel-container:$(docker inspect -f '{{"{{"}}json .Config.WorkingDir{{"}}"}}' gat-sentinel-container | sed 's/\"//g')/ || true"`,
		`/bin/bash -c "docker commit gat-sentinel-container gat-sentinel0"`,
		`/bin/bash -c "GSUTILOPT=$([ -f {{ .Workdir }}/credentials ] && echo Credentials:gs_service_key_file=./credentials || echo s3:host=s3-$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region).amazonaws.com) ; function gsutil { docker run --rm --entrypoint bash gat-sentinel0 -c \"gsutil -m -o $GSUTILOPT $*\" ; } ; function ere_quote { sed 's/[][\\.|$(){}?+*^]/\\\\&/g' <<< \"$*\" ; } ; function gsutil_cat { if [ -d {{ .Bucket }} ]; then cat $1 ; else gsutil cat $1 ; fi } ; KEY=$(docker inspect --format '{{"{{"}}index .Config.Labels \"cache-key\"{{"}}"}}' gat-sentinel-container) ; for cache in $(docker inspect --format '{{"{{"}}join (split (index .Config.Labels \"cache\") \":\") \" \"{{"}}"}}' gat-sentinel-container) ; do LINE=$(gsutil_cat {{ .Bucket }}/run-caches/manifest.$KEY 2>/dev/null | grep -E -- \"^$(ere_quote $cache) \") ; if [ ! -z \"$LINE\" ]; then gsutil_cat {{ .Bucket }}/run-caches/$${LINE#* } | docker cp - gat-sentinel-container:$(dirname $${LINE% *}) ; fi ; done "`,
		`/usr/bin/docker rmi gat-sentinel0`,
		`/bin/bash -c "docker commit gat-sentinel-container gat-sentinel0"`,
		`/usr/bin/docker rm gat-sentinel-container`,
		`/bin/bash -c "ENTRYPOINT0=$(docker inspect -f '{{"{{"}}json .Config.Entrypoint{{"}}"}}' {{ .Tag }}) ; CMD0=$(docker inspect -f '{{"{{"}}json .Config.Cmd{{"}}"}}' {{ .Tag }}) ; ENTRYPOINT=$(if [ \"$ENTRYPOINT0\" = \"null\" ] ; then echo [] ; else echo $ENTRYPOINT0 ; fi) ; CMD=$(if [ \"$CMD0\" = \"null\" ] ; then echo [] ; else echo $CMD0 ; fi) ; printf \"FROM gat-sentinel0\nENTRYPOINT $ENTRYPOINT\nCMD $CMD\n\" | docker build -t gat-sentinel -"`,
		`/usr/bin/docker rmi gat-sentinel0`,
	}
	// docker commit -c "ENTRYPOINT []" does not clear entrypoint.  Use build.
	gat1 = []string{
		`/bin/bash -c "docker run --network host{{ .Gpus }}{{ range .Envs }}{{ . | printf " --env %s" }}{{ end }} --env {{ .ServiceAccountEnv }}=$(docker inspect -f '{{"{{"}}json .Config.WorkingDir{{"}}"}}' {{ .Tag }} | sed 's/\"//g')/credentials --privileged{{ if .User }}{{ .User | printf " --user %s" }}{{ end }} -v /dev:/dev --name gat-run-container gat-sentinel{{ if .Cmd }} {{ .Cmd }}{{ end }}"`,
		`/usr/bin/docker commit gat-run-container gat-run`,
		`/usr/bin/docker rm gat-run-container`,
		`/usr/bin/docker rmi gat-sentinel`,
		`/bin/bash -c "[ -d {{ .Bucket }} ] && mkdir -p {{ .Bucket }}/run-local || true"`,
		`/bin/bash -c "GSUTILOPT=$([ -f {{ .Workdir }}/credentials ] && echo Credentials:gs_service_key_file=$(realpath {{ .Workdir }}/credentials) || echo s3:host=s3-$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region).amazonaws.com) ; docker run --name gat-cache-container -v $([ -d {{ .Bucket }} ] && echo -n {{ .Bucket }} || echo -n $(pwd)):/hostpwd --entrypoint \"/bin/bash\" gat-run -c \"( [ \\$(realpath .) = '/' ] && export SYSDIRS='\\( -name boot -o -name dev -o -name etc -o -name home -o -name lib -o -name lib64 -o -name media -o -name mnt -o -name opt -o -name proc -o -name run -o -name sbin -o -name srv -o -name sys -o -name tmp -o -name usr -o -name var -o -name bin \\) -prune -o' ; for f in \\$(eval find . \\$SYSDIRS -not -path \\'*/.*\\' -type f -newer sentinel -print) ; do mkdir -p ./run-local/\\$(dirname \\$f) ; ln \\$(realpath \\$f) ./run-local/\\$f ; done ; ) && ( if [ -d ./run-local ]; then gsutil -m -o $GSUTILOPT rsync -r run-local $([ -d {{ .Bucket }} ] && echo -n /hostpwd/run-local || echo -n {{ .Bucket }}) ; fi ) \""`,
		// https://stackoverflow.com/a/16951928/5132008 R. Galli
		`/bin/bash -c "GSUTILOPT=$([ -f {{ .Workdir }}/credentials ] && echo Credentials:gs_service_key_file=$(realpath {{ .Workdir }}/credentials) || echo s3:host=s3-$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region).amazonaws.com) ; function gsutil { docker run --rm --entrypoint bash gat-run -c \"gsutil -m -o $GSUTILOPT $*\" ; } ; function ere_quote { sed 's/[][\\.|$(){}?+*^]/\\\\&/g' <<< \"$*\" ; } ; function gsutil_cat { if [ -d {{ .Bucket }} ]; then cat $1 ; else gsutil cat $1 ; fi } ; function gsutil_cp { if [ -d {{ .Bucket }} ]; then cp $1 $2 ; else docker run -v $(dirname $1):/hostpwd --rm --entrypoint bash gat-run -c \"gsutil -m -o $GSUTILOPT cp /hostpwd/\\$(basename $1) $2\" ; fi ; } ; KEY=$(docker inspect --format '{{"{{"}}index .Config.Labels \"cache-key\"{{"}}"}}' gat-cache-container) ; for cache in $(docker inspect --format '{{"{{"}}join (split (index .Config.Labels \"cache\") \":\") \" \"{{"}}"}}' gat-cache-container) ; do if ! gsutil_cat {{ .Bucket }}/run-caches/manifest.$KEY 2>/dev/null | grep -E -- \"^$(ere_quote $cache) \" ; then RAND=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 7 ; echo ''); docker cp gat-cache-container:$cache - > /var/tmp/$RAND.tar ; echo \"$cache $RAND.tar\" >> /var/tmp/manifest.$KEY ; for f in $RAND.tar manifest.$KEY ; do gsutil_cp /var/tmp/$f {{ .Bucket }}/run-caches/$f ; done ; rm -f /var/tmp/$RAND.tar; fi ; done ; rm -f /var/tmp/manifest.$KEY ;"`,
		`/usr/bin/docker rm gat-cache-container`,
	}
	gat2 = []string{
		`/bin/bash -c "GSUTILOPT=$([ -f {{ .Workdir }}/credentials ] && echo Credentials:gs_service_key_file=/hostpwd/credentials || echo s3:host=s3-$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region).amazonaws.com) ; journalctl -b -o cat --no-pager -u gat1 > /var/tmp/gat1.out ; if [ -d {{ .Bucket }} ]; then mv /var/tmp/gat1.out {{ .Bucket }}/run-local/gat.$(date +%s) ; else docker run -v /var/tmp:/hostpwd --rm --entrypoint bash gat-run -c \"gsutil -m -o $GSUTILOPT cp /hostpwd/gat1.out {{ .Bucket }}/gat.\\$(date +%%s)\" ; fi ;"`,
		`/usr/bin/docker rmi gat-run`,
	}
)

const templAws string = `#cloud-config
users:
- default

write_files:
- path: /etc/systemd/system/cloudwatch-agent.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Run cloudwatch agent

    [Service]
    User=root
    Type=oneshot
    ExecStart=/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json

- path: /etc/systemd/system/vector.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Vector

    [Service]
    User=root
    ExecStart=/root/.vector/bin/vector

- path: /etc/vector/vector.toml
  permissions: 0644
  owner: root
  content: |
    [sources.journal-in]
      type = "journald"
      data_dir = "/var/tmp"
      include_units = ["gat0", "gat1", "gat2", "shutdown"]

    [sinks.journal-out]
      encoding.codec = "json"
      group_name = "{{ .Tag | ReplaceColon }}"
      inputs = ["journal-in"]
      region = "{{ .Region }}"
      stream_name = "journal"
      type = "aws_cloudwatch_logs"

- path: /etc/systemd/system/gat0.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Write service account json

    [Service]
    Environment="HOME={{ .Workdir }}"
    WorkingDirectory={{ .Workdir }}
    User=ec2-user
    Type=oneshot
    ExecStart=/bin/bash -c "eval $(aws --region $(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region) ecr get-login --no-include-email)"
    ExecStart=/bin/bash -c "/usr/bin/docker pull {{ .RepositoryUri }}"
    ExecStart=/usr/bin/docker tag {{ .RepositoryUri }} {{ .Tag }}
{{ range .Gat0 }}{{ . | printf "    ExecStart=%s\n" }}{{ end }}

- path: /etc/systemd/system/gat1.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Run user experiment and upload results
    After=gat0.service

    [Service]
    User=ec2-user
    Environment="HOME={{ .Workdir }}"
    WorkingDirectory={{ .Workdir }}
    Type=oneshot
{{ range .Gat1 }}{{ . | printf "    ExecStart=%s\n" }}{{ end }}

- path: /etc/systemd/system/gat1a.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Halt in-docker notebook server

    [Service]
    User=ec2-user
    Environment="HOME={{ .Workdir }}"
    WorkingDirectory={{ .Workdir }}
    Type=oneshot
    ExecStart=/bin/bash -c "docker exec gat-run-container start.sh pkill jupyter"

- path: /etc/systemd/system/gat2.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Dump gat1 output to bucket
    After=gat1.service

    [Service]
    Environment="HOME={{ .Workdir }}"
    WorkingDirectory={{ .Workdir }}
    Type=oneshot
{{ range .Gat2 }}{{ . | printf "    ExecStart=%s\n" }}{{ end }}

- path: /etc/systemd/system/shutdown.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Shutdown
    After=gat2.service

    [Service]
    Environment="HOME={{ .Workdir }}"
    WorkingDirectory={{ .Workdir }}
    Type=oneshot
    ExecStart=/bin/bash -c "aws ec2 --region $(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region) terminate-instances --instance-ids $(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .instanceId)"

`

const templGce string = `#cloud-config
users:
- default

write_files:
- path: /etc/systemd/system/config-firewall.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Configures the host firewall

    [Service]
    Type=oneshot
    RemainAfterExit=true
    ExecStart=/sbin/iptables -A INPUT -p tcp --dport 8888 -j ACCEPT

- path: /etc/systemd/system/nvidia-uvm.service
  permissions: 0755
  owner: root
  content: |
    [Unit]
    Description=Pick up /dev/nvidia-uvm
    Requires=network-online.target gcr-online.target
    After=network-online.target gcr-online.target

    [Service]
    User=root
    Type=oneshot
    ExecStart=/bin/bash -c "if [ -e /dev/nvidia0 ] ; then /sbin/modprobe -a nvidia-uvm ; fi"

- path: /etc/systemd/system/cuda-vector-add.service
  permissions: 0755
  owner: root
  content: |
    [Unit]
    Description=Run a CUDA Vector Addition Workload
    After=docker.service nvidia-uvm.service
    Wants=docker.service nvidia-uvm.service

    [Service]
    User=root
    Type=oneshot
    ExecStart=/bin/bash -c "if [ -e /dev/nvidia0 ] ; then /usr/bin/docker run --volume /usr/lib64:/usr/local/nvidia/lib64 --volume /opt/bin:/usr/local/nvidia/bin --device /dev/nvidia0:/dev/nvidia0 --device /dev/nvidia-uvm:/dev/nvidia-uvm --device /dev/nvidiactl:/dev/nvidiactl gcr.io/google_containers/cuda-vector-add:v0.1 ; fi"

- path: /etc/systemd/system/gat0.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Write service account json
    After=docker.service nvidia-uvm.service config-firewall.service
    Wants=docker.service nvidia-uvm.service config-firewall.service

    [Service]
    Environment="HOME={{ .Workdir }}"
    WorkingDirectory={{ .Workdir }}
    Type=oneshot
    ExecStart=/bin/bash -c "echo $'{{ .ServiceAccountJsonContent }}' >{{ .Workdir }}/credentials && chmod 600 {{ .Workdir }}/credentials"
    ExecStart=/usr/bin/docker-credential-gcr configure-docker
    ExecStart=/bin/bash -c "{{ .ServiceAccountEnv }}={{ .Workdir }}/credentials /usr/bin/docker pull {{ .RepositoryUri }}"
    ExecStart=/usr/bin/docker tag {{ .RepositoryUri }} {{ .Tag }}
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

- path: /etc/systemd/system/gat1a.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Halt in-docker notebook server

    [Service]
    Environment="HOME={{ .Workdir }}"
    WorkingDirectory={{ .Workdir }}
    Type=oneshot
    ExecStart=/bin/bash -c "/usr/bin/docker exec gat-run-container start.sh pkill jupyter"

- path: /etc/systemd/system/gat2.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Dump gat1 output to bucket
    After=gat1.service

    [Service]
    Environment="HOME={{ .Workdir }}"
    WorkingDirectory={{ .Workdir }}
    Type=oneshot
{{ range .Gat2 }}{{ . | printf "    ExecStart=%s\n" }}{{ end }}

- path: /etc/systemd/system/shutdown.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Shutdown
    After=gat2.service

    [Service]
    Environment="HOME={{ .Workdir }}"
    WorkingDirectory={{ .Workdir }}
    Type=oneshot
    ExecStart=/bin/bash -c "sleep 30 && systemctl stop stackdriver-logging"
    ExecStart=/bin/bash -c "curl -s --retry 2 -H \"Authorization: Bearer $(curl -s --retry 2 http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/$(cat {{ .Workdir }}/credentials | jq -r -c '.client_email')/token -H 'Metadata-Flavor: Google' | jq -r -c '.access_token')\" -X DELETE https://compute.googleapis.com/compute/v1/$(curl -s --retry 2 http://metadata.google.internal/computeMetadata/v1/instance/zone -H 'Metadata-Flavor: Google')/instances/$(curl -s --retry 2 http://metadata.google.internal/computeMetadata/v1/instance/id -H 'Metadata-Flavor: Google')"

`

func DockerCommands(c *cli.Context, tag string, bucket string, envs []string) string {
	// double evaluation: could not get template {{block}} {{end}} to work.
	commands := `
{{ range .Gat0 }}{{ . | printf "%s\n" }}{{ end }}
{{ range .Gat1 }}{{ . | printf "%s\n" }}{{ end }}
{{ range .Gat2 }}{{ . | printf "%s\n" }}{{ end }}
`
	for i := 0; i < 2; i++ {
		t := template.Must(template.New("CloudConfig").Parse(commands))
		var buf bytes.Buffer
		if err := t.Execute(&buf, CloudConfig{
			Tag:                       tag,
			Bucket:                    bucket,
			ServiceAccountJsonContent: "dummy",
			ServiceAccountEnv:         "dummy",
			Envs:                      envs,
			Workdir:                   "",
			Gpus:                      "",
			Gat0:                      gat0,
			Gat1:                      gat1,
			Gat2:                      gat2,
			Cmd:                       c.String("command"),
		}); err != nil {
			panic(err)
		}
		commands = buf.String()
	}
	return commands
}

func UserDataAws(c *cli.Context, tag string, repositoryUri string, bucket string, qGpu bool, region string, envs []string) string {
	runcmd := []string{"daemon-reload", "start vector.service", "start gat0.service", "start gat1.service", "start gat2.service"}
	if !c.Bool("noshutdown") {
		runcmd = append(runcmd, "start shutdown.service")
	}
	userdata := templAws
	userdata += "runcmd:\n"
	for _, value := range runcmd {
		userdata += fmt.Sprintf("- systemctl %s\n", value)
	}
	var gpus string
	if qGpu {
		gpus = " --gpus all"
	}
	// double evaluation: could not get template {{block}} {{end}} to work.
	for i := 0; i < 2; i++ {
		t := template.Must(template.New("CloudConfig").Funcs(template.FuncMap{
			"ReplaceColon": func(x string) string {
				return strings.ReplaceAll(x, ":", "-")
			},
		}).Parse(userdata))
		var buf bytes.Buffer
		if err := t.Execute(&buf, CloudConfig{
			Tag:               tag,
			Region:            region,
			RepositoryUri:     repositoryUri,
			Bucket:            bucket,
			ServiceAccountEnv: "AWS_SHARED_CREDENTIALS_FILE",
			Envs:              envs,
			User:              c.String("user"),
			Workdir:           "/home/ec2-user",
			Gpus:              gpus,
			Gat0:              gat0,
			Gat1:              gat1,
			Gat2:              gat2,
			Cmd:               c.String("command"),
		}); err != nil {
			panic(err)
		}
		userdata = buf.String()
	}
	return b64.StdEncoding.EncodeToString([]byte(userdata))
}

func UserDataGce(c *cli.Context, tag string, repositoryUri string, bucket string, qGpu bool, serviceAccountJsonContent string, envs []string) string {
	runcmd := []string{"daemon-reload", "start stackdriver-logging", "start config-firewall.service", "start nvidia-uvm.service", "start cuda-vector-add.service", "start gat0.service", "start gat1.service", "start gat2.service"}
	if !c.Bool("noshutdown") {
		runcmd = append(runcmd, "start shutdown.service")
	}

	userdata := templGce
	userdata += "runcmd:\n"
	for _, value := range runcmd {
		userdata += fmt.Sprintf("- systemctl %s\n", value)
	}
	var gpus string
	if qGpu {
		gpus = " --gpus all"
	}
	// double evaluation: could not get template {{block}} {{end}} to work.
	for i := 0; i < 2; i++ {
		t := template.Must(template.New("CloudConfig").Parse(userdata))
		var buf bytes.Buffer
		if err := t.Execute(&buf, CloudConfig{
			Tag:                       tag,
			RepositoryUri:             repositoryUri,
			Bucket:                    bucket,
			ServiceAccountJsonContent: serviceAccountJsonContent,
			ServiceAccountEnv:         "GOOGLE_APPLICATION_CREDENTIALS",
			Envs:                      envs,
			User:                      c.String("user"),
			Workdir:                   "/var/tmp",
			Gpus:                      gpus,
			Gat0:                      gat0,
			Gat1:                      gat1,
			Gat2:                      gat2,
			Cmd:                       c.String("command"),
		}); err != nil {
			panic(err)
		}
		userdata = buf.String()
	}
	return userdata
}

func Shutdown(c *cli.Context, tag string) string {
	templ := `
#!/bin/bash

# REST API key deletion of {{ .Tag }}
`
	t := template.Must(template.New("cloudConfig").Parse(templ))
	var buf bytes.Buffer
	if err := t.Execute(&buf, CloudConfig{
		Tag: tag,
	}); err != nil {
		panic(err)
	}
	return buf.String()
}
