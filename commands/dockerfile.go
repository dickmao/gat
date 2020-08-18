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
  && DEBIAN_FRONTEND=noninteractive apt-get -y install gnupg wget python \
  && export GCSFUSE_REPO=gcsfuse-$(grep CODENAME /etc/lsb-release | egrep -o "[^=]+$") \
  && echo "deb http://packages.cloud.google.com/apt $GCSFUSE_REPO main" | tee /etc/apt/sources.list.d/gcsfuse.list \
  && wget -qO- https://packages.cloud.google.com/apt/doc/apt-key.gpg | APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1 apt-key add - \
  && apt-get -yq update \
  && DEBIAN_FRONTEND=noninteractive apt-get -y install gcsfuse curl automake libfuse-dev libcurl4-gnutls-dev libxml2-dev libssl-dev \
  && curl -sLk https://github.com/s3fs-fuse/s3fs-fuse/archive/master.tar.gz | tar xfz - \
  && ( cd s3fs-fuse-master ; ./autogen.sh ; ./configure ; make install ) \
  && wget -q https://storage.googleapis.com/pub/gsutil.tar.gz \
  && tar xfz gsutil.tar.gz -C /opt \
  && rm -f gsutil.tar.gz \
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
