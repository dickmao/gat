package commands

import (
	"bytes"
	"context"
	"text/template"

	"github.com/docker/docker/client"
	"github.com/urfave/cli/v2"
)

func DockerfileSource(c *cli.Context, cli *client.Client, imageId string) []byte {
	const templ string = `FROM {{ .ImageId }}
{{if .User}}USER root
{{end}}RUN \
  apt-get -yq update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y apt-utils 2>&1 | grep -v "delaying" \
  && DEBIAN_FRONTEND=noninteractive apt-get -y install gnupg wget python s3fs fuse \
  && wget -q https://storage.googleapis.com/pub/gsutil.tar.gz \
  && tar xfz gsutil.tar.gz -C /opt \
  && rm -f gsutil.tar.gz \
  && wget -q https://github.com/dickmao/gcsfuse/files/5165307/gcsfuse.zip \
  && unzip gcsfuse.zip \
  && mv gcsfuse /usr/local/bin \
  && rm -f gcsfuse.zip \
{{if .User}}  && chown -R {{ .User }} /opt/gsutil \
{{end}}  && ln -s /opt/gsutil/gsutil /usr/local/bin
{{if .User}}USER {{ .User }}
{{end}}
`
	var buf bytes.Buffer
	if inspect, _, err := cli.ImageInspectWithRaw(context.Background(), imageId); err != nil {
		panic(err)
	} else {
		t := template.Must(template.New("DockerfileSource").Parse(templ))

		if err := t.Execute(&buf, struct {
			ImageId string
			User    string
		}{
			imageId,
			inspect.Config.User,
		}); err != nil {
			panic(err)
		}
	}
	return buf.Bytes()
}
