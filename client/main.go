package client

import (
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"github.com/tinkerbell/tink/protos/hardware"
	"github.com/tinkerbell/tink/protos/template"
	"github.com/tinkerbell/tink/protos/workflow"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// gRPC clients.
var (
	TemplateClient template.TemplateServiceClient
	WorkflowClient workflow.WorkflowServiceClient
	HardwareClient hardware.HardwareServiceClient
)

// FullClient aggregates all the gRPC clients available from Tinkerbell Server.
type FullClient struct {
	TemplateClient template.TemplateServiceClient
	WorkflowClient workflow.WorkflowServiceClient
	HardwareClient hardware.HardwareServiceClient
}

// NewFullClient returns a FullClient. A structure that contains all the
// clients made available from tink-server.
func NewFullClient(conn grpc.ClientConnInterface) *FullClient {
	return &FullClient{
		TemplateClient: template.NewTemplateServiceClient(conn),
		WorkflowClient: workflow.NewWorkflowServiceClient(conn),
		HardwareClient: hardware.NewHardwareServiceClient(conn),
	}
}

type ConnOptions struct {
	CertURL       string
	GRPCAuthority string
}

func (o *ConnOptions) SetFlags(flagSet *pflag.FlagSet) {
	flagSet.StringVar(&o.CertURL, "tinkerbell-cert-url", "http://127.0.0.1:42114/cert", "The URL where the certificate is located")
	flagSet.StringVar(&o.GRPCAuthority, "tinkerbell-grpc-authority", "127.0.0.1:42113", "Link to tink-server grcp api")
}

// This function is bad and ideally should be removed, but for now it moves all the bad into one place.
// This is the legacy of packethost/cacher running behind an ingress that couldn't terminate TLS on behalf
// of GRPC. All of this functionality should be ripped out in favor of either using trusted certificates
// or moving the establishment of trust in the certificate out to the environment (or running in insecure mode
// e.g. for development.)
func grpcCredentialFromCertEndpoint(url string) (credentials.TransportCredentials, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, errors.Wrap(err, "fetch cert")
	}
	defer resp.Body.Close()
	certs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read cert")
	}
	cp := x509.NewCertPool()
	ok := cp.AppendCertsFromPEM(certs)
	if !ok {
		return nil, errors.Wrap(err, "parse cert")
	}
	return credentials.NewClientTLSFromCert(cp, ""), nil
}

func NewClientConn(opt *ConnOptions) (*grpc.ClientConn, error) {
	creds, err := grpcCredentialFromCertEndpoint(opt.CertURL)
	if err != nil {
		return nil, errors.Wrap(err, "obtain trusted certificate")
	}
	conn, err := grpc.Dial(opt.GRPCAuthority, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, errors.Wrap(err, "connect to tinkerbell server")
	}
	return conn, nil
}

// GetConnection returns a gRPC client connection.
func GetConnection() (*grpc.ClientConn, error) {
	certURL := os.Getenv("TINKERBELL_CERT_URL")
	if certURL == "" {
		return nil, errors.New("undefined TINKERBELL_CERT_URL")
	}

	grpcAuthority := os.Getenv("TINKERBELL_GRPC_AUTHORITY")
	if grpcAuthority == "" {
		return nil, errors.New("undefined TINKERBELL_GRPC_AUTHORITY")
	}

	creds, err := grpcCredentialFromCertEndpoint(certURL)
	if err != nil {
		return nil, errors.Wrap(err, "obtain trusted certificate")
	}
	conn, err := grpc.Dial(grpcAuthority,
		grpc.WithTransportCredentials(creds),
		grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor()),
		grpc.WithStreamInterceptor(otelgrpc.StreamClientInterceptor()),
	)
	if err != nil {
		return nil, errors.Wrap(err, "connect to tinkerbell server")
	}
	return conn, nil
}

// Setup : create a connection to server.
func Setup() error {
	conn, err := GetConnection()
	if err != nil {
		return err
	}
	TemplateClient = template.NewTemplateServiceClient(conn)
	WorkflowClient = workflow.NewWorkflowServiceClient(conn)
	HardwareClient = hardware.NewHardwareServiceClient(conn)
	return nil
}

// TinkHardwareClient creates a new hardware client.
func TinkHardwareClient() (hardware.HardwareServiceClient, error) {
	conn, err := GetConnection()
	if err != nil {
		log.Fatal(err)
	}
	return hardware.NewHardwareServiceClient(conn), nil
}

// TinkWorkflowClient creates a new workflow client.
func TinkWorkflowClient() (workflow.WorkflowServiceClient, error) {
	conn, err := GetConnection()
	if err != nil {
		log.Fatal(err)
	}
	return workflow.NewWorkflowServiceClient(conn), nil
}
