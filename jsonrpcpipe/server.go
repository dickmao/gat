package jsonrpcpipe

import (
	"io"
	"os"

	"./gat/net/rpc"
	"./gat/net/rpc/jsonrpc"
)

type nullWriter struct {
	io.ReadCloser
}

func (nullWriter) Write(b []byte) (n int, err error) {
	// return ioutil.Discard.Write(b)
	return os.Stdout.Write(b)
}

func NullWriter(conn io.ReadCloser) io.ReadWriteCloser {
	return &nullWriter{conn}
}

func ServeConn(conn io.ReadCloser) {
	rpc.ServeCodec(jsonrpc.NewServerCodec(NullWriter(conn)))
}
