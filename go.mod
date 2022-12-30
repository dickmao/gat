module github.com/dickmao/gat

go 1.13

// https://github.com/moby/buildkit/pull/1425
replace github.com/containerd/containerd => github.com/containerd/containerd v1.3.1-0.20200227195959-4d242818bf55

replace github.com/docker/docker => github.com/docker/docker v1.4.2-0.20200227233006-38f52c9fec82

require (
	cloud.google.com/go v0.60.0 // indirect
	cloud.google.com/go/logging v1.0.0
	cloud.google.com/go/storage v1.10.0
	github.com/Microsoft/hcsshim v0.8.9 // indirect
	github.com/aws/aws-sdk-go v1.33.0
	github.com/containerd/continuity v0.0.0-20200710164510-efbc4488d8fe // indirect
	github.com/dickmao/git2go/v32 v32.0.1-0.20201110230406-ba23003dc8d8
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker v17.12.0-ce-rc1.0.20200309214505-aa6a9891b09c+incompatible
	github.com/docker/go-metrics v0.0.1 // indirect
	github.com/docker/go-units v0.4.0
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/google/go-containerregistry v0.1.1
	github.com/gorilla/mux v1.7.4 // indirect
	github.com/opencontainers/go-digest v1.0.0
	github.com/pelletier/go-toml v1.8.0
	github.com/prometheus/client_golang v1.7.1 // indirect
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/viper v1.7.1
	github.com/urfave/cli/v2 v2.2.0
	go.opencensus.io v0.22.4 // indirect
	golang.org/x/net v0.0.0-20200707034311-ab3426394381 // indirect
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/sys v0.0.0-20200722175500-76b94024e4b6 // indirect
	golang.org/x/text v0.3.3 // indirect
	golang.org/x/tools v0.0.0-20200709181711-e327e1019dfe // indirect
	google.golang.org/api v0.29.0
	google.golang.org/genproto v0.0.0-20200722002428-88e341933a54 // indirect
	google.golang.org/grpc v1.30.0 // indirect
	gotest.tools/v3 v3.0.2 // indirect
)
