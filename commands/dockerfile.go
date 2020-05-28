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
ENV GRANT_SUDO yes
USER root
RUN \
  apt-get -yq update \
  && DEBIAN_FRONTEND=noninteractive apt-get -y install gnupg \
  && export GCSFUSE_REPO=gcsfuse-$(grep CODENAME /etc/lsb-release | egrep -o "[^=]+$") \
  && echo "deb http://packages.cloud.google.com/apt $GCSFUSE_REPO main" | tee /etc/apt/sources.list.d/gcsfuse.list \
  && wget -qO- https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -  \
  && apt-get -yq update \
  && DEBIAN_FRONTEND=noninteractive apt-get -y install gcsfuse \
  && wget -q https://storage.googleapis.com/pub/gsutil.tar.gz \
  && tar xfz gsutil.tar.gz -C /opt \
  && rm -f gsutil.tar.gz \
  && chown -R {{ .User }} /opt/gsutil \
  && ln -s /opt/gsutil/gsutil /usr/local/bin
USER {{ .User }}
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
