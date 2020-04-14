package commands

import (
	"bytes"
	"text/template"
)

type CloudConfig struct {
	Project                   string
	Tag                       string
	Bucket                    string
	ServiceAccountJson        string
	ServiceAccountJsonContent string
}

func UserData(config CloudConfig) string {
	templ := `
#cloud-config

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
    Environment="HOME=/var/tmp"
    WorkingDirectory=/var/tmp
    Type=oneshot
    ExecStart=/bin/bash -c "echo $'{{ .ServiceAccountJsonContent }}' >$(basename {{ .ServiceAccountJson }})"
    ExecStart=/usr/bin/docker-credential-gcr configure-docker
    ExecStart=/usr/bin/docker pull gcr.io/{{ .Project }}/{{ .Tag }}
    ExecStart=/usr/bin/docker tag gcr.io/{{ .Project }}/{{ .Tag }} {{ .Tag }}
    ExecStart=/bin/bash -c "/usr/bin/docker run --entrypoint \"/bin/bash\" --name gat-sentinel-container -v $(pwd):/hosthome {{ .Tag }} -c \"cp /hosthome/$(basename {{ .ServiceAccountJson }}) . && chmod 600 ./$(basename {{ .ServiceAccountJson }}) && touch sentinel\""

- path: /etc/systemd/system/gat1.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Run user experiment and upload results
    After=gat0.service

    [Service]
    Environment="HOME=/var/tmp"
    WorkingDirectory=/var/tmp
    Type=oneshot
    ExecStart=/bin/bash -c "/usr/bin/docker commit -c \"ENTRYPOINT $(docker inspect -f '{{"{{"}}json .Config.Entrypoint{{"}}"}}' {{ .Tag }})\" -c \"CMD $(docker inspect -f '{{"{{"}}json .Config.Cmd{{"}}"}}' {{ .Tag }})\" gat-sentinel-container gat-sentinel"
    ExecStart=/usr/bin/docker rm gat-sentinel-container
    ExecStart=/usr/bin/docker run --privileged --name gat-run-container gat-sentinel
    ExecStart=/bin/bash -c "/usr/bin/docker commit gat-run-container gat-run"
    ExecStart=/usr/bin/docker rm gat-run-container
    ExecStart=/usr/bin/docker run --rm --entrypoint "/bin/bash" gat-run -c "( for f in $(find . -not -path '*/\.*' -type f -newer sentinel) ; do mkdir -p ./results/$(dirname $f) ; ln -s $(realpath $f) ./results/$f ; done ; ) && gsutil -m -o Credentials:gs_service_key_file=$(realpath ./service-account.json) rsync -r results gs://{{ .Bucket }}/results"

- path: /etc/systemd/system/shutdown.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Shutdown
    After=gat1.service

    [Service]
    Environment="HOME=/var/tmp"
    WorkingDirectory=/var/tmp
    Type=oneshot
    ExecStart=/usr/bin/docker pull stedolan/jq
    ExecStart=/bin/bash -c "curl -s --retry 2 -H \"Authorization: Bearer $(curl -s --retry 2 http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/$(cat /var/tmp/service-account.json | /usr/bin/docker run --rm -i stedolan/jq -rc '.client_email')/token -H 'Metadata-Flavor: Google' | /usr/bin/docker run --rm -i stedolan/jq -rc '.access_token')\" -X DELETE https://compute.googleapis.com/compute/v1/$(curl -s --retry 2 http://metadata.google.internal/computeMetadata/v1/instance/zone -H 'Metadata-Flavor: Google')/instances/$(curl -s --retry 2 http://metadata.google.internal/computeMetadata/v1/instance/id -H 'Metadata-Flavor: Google')"

runcmd:
- systemctl daemon-reload
- systemctl start gat0.service
- systemctl start gat1.service
- systemctl start shutdown.service
`
	t := template.Must(template.New("cloudConfig").Parse(templ))
	var buf bytes.Buffer
	if err := t.Execute(&buf, config); err != nil {
		panic(err)
	}
	return buf.String()
}

func Shutdown(config CloudConfig) string {
	templ := `
#!/bin/bash

# REST API key deletion of {{ .Project }}{{ .Tag }}
`
	t := template.Must(template.New("cloudConfig").Parse(templ))
	var buf bytes.Buffer
	if err := t.Execute(&buf, config); err != nil {
		panic(err)
	}
	return buf.String()
}
