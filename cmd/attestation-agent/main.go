// Package main implements a server for attestation agent service.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"encoding/json"
	"encoding/base64"
	"google.golang.org/grpc"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/keyprovider"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/skr"
)

type AzureInformation struct {
	// Endpoint of the certificate cache service from which
	// the certificate chain endorsing hardware attestations
	// can be retrieved. This is optinal only when the container
	// will expose attest/maa and key/release APIs.
	CertCache attest.CertCache `json:"certcache,omitempty"`

	// Identifier of the managed identity to be used
	// for authenticating with AKV MHSM. This is optional and
	// useful only when the container group has been assigned
	// more than one managed identity.
	Identity common.Identity `json:"identity,omitempty"`
}

var info AzureInformation
var privateKey []byte

type DecryptConfig struct {
	Parameters map[string][]string
}

type EncryptConfig struct {
	Parameters map[string][]string
	Dc DecryptConfig
}

type KeyWrapParams struct {
    Ec EncryptConfig `json:"ec,omitempty"`
    Optsdata string `json:"optsdata,omitempty"`
}

type KeyUnwrapParams struct {
    Dc DecryptConfig `json:"dc,omitempty"`
    Annotation string `json:"annotation"`
}

type AnnotationPacket struct {
    Kid string `json:"kid"`
    WrappedData []byte `json:"wrapped_data"`
    Iv []byte `json:"iv,omitempty"`
    WrapType string `json:"wrap_type,omitempty"`
    MhsmEndpoint string `json:"mhsm_endpoint,omitempty"`
    MaaEndpoint string `json:"maa_endpoint,omitempty"`
}

type keyProviderInput struct {
    // Operation is either "keywrap" or "keyunwrap"
    // attestation-agent can only handle the case of "keyunwrap"
    Op string `json:"op"`
    // For attestation-agent, keywrapparams should be empty.
    KeyWrapParams KeyWrapParams `json:"keywrapparams,omitempty"`
    KeyUnwrapParams KeyUnwrapParams `json:"keyunwrapparams,omitempty"`
}

// server is used to implement helloworld.GreeterServer.
type server struct {
	keyprovider.UnimplementedKeyProviderServiceServer
}

func (s *server) SayHello(ctx context.Context, in *keyprovider.HelloRequest) (*keyprovider.HelloReply, error) {
	log.Printf("Received: %v", in.GetName())
	return &keyprovider.HelloReply{Message: "Hello " + in.GetName()}, nil
}

func (s *server) UnWrapKey(c context.Context, grpcInput *keyprovider.KeyProviderKeyWrapProtocolInput) (*keyprovider.KeyProviderKeyWrapProtocolOutput, error) {
	var input keyProviderInput
	str := string(grpcInput.KeyProviderKeyWrapProtocolInput)
	err := json.Unmarshal(grpcInput.KeyProviderKeyWrapProtocolInput, &input)
	if err != nil {
		log.Fatalf("Ill-formed key provider input: %v. Error: %v", str, err.Error())
	}
	log.Printf("Key provider input: %v", input)

	var dc = input.KeyUnwrapParams.Dc
	if len(dc.Parameters["attestation-agent"]) == 0 {
		log.Fatalf("attestation-agent must be specified in decryption config parameters: %v", str)
	}
	attestation_agent_name := dc.Parameters["attestation-agent"][0]
	log.Printf("Attestation agent name: %v", attestation_agent_name)

	// TODO: use AKV/MHSM/other for decryption based on the attestation-agent parameter

	var annotationBytes []byte
	annotationBytes, err = base64.StdEncoding.DecodeString(input.KeyUnwrapParams.Annotation)
	if err != nil {
		log.Fatalf("Annotation is not a base64 encoding: %v. Error: %v", input.KeyUnwrapParams.Annotation, err.Error())
	}
	log.Printf("Decoded annotation: %v", string(annotationBytes))

	var annotation AnnotationPacket
	err = json.Unmarshal(annotationBytes, &annotation)
	if err != nil {
		log.Fatalf("Ill-formed annotation packet: %v. Error: %v", input.KeyUnwrapParams.Annotation, err.Error())
	}
	log.Printf("Annotation packet: %v", annotation)

	mhsm := skr.MHSM{
		Endpoint:    annotation.MhsmEndpoint,
		APIVersion:  "api-version=7.3-preview",
	}

	maa := attest.MAA{
		Endpoint:   annotation.MaaEndpoint,
		TEEType:    "SevSnpVM",
		APIVersion: "api-version=2020-10-01",
	}

	skrKeyBlob := skr.KeyBlob{
		KID:       annotation.Kid,
		Authority: maa,
		MHSM:      mhsm,
	}

	// MHSM has limit on the request size. We do not pass the EncodedSecurityPolicy here so
	// it is not presented as fine-grained init-time claims in the MAA token, which would
	// introduce larger MAA tokens that MHSM would accept
	keyBytes, err := skr.SecureKeyRelease("", info.CertCache, info.Identity, skrKeyBlob)

	if err != nil {
		log.Fatalf("SKR failed: %v", err)
	}

       //err = os.WriteFile("skrout", keyBytes, 0644)

       key, err := x509.ParsePKCS8PrivateKey(keyBytes)
       if err != nil {
                log.Fatalf("Released key is invalid: %v", err)
        }

       if privkey, ok := key.(*rsa.PrivateKey); ok {
               plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privkey, annotation.WrappedData)
               if err != nil {
                       log.Fatalf("Decryption failed: %v", err)
               }
               //log.Printf("plain text: %v", string(plaintext))
		 out := new(keyprovider.KeyProviderKeyWrapProtocolOutput)
		out.KeyProviderKeyWrapProtocolOutput = plaintext
		return out, nil
       }

	log.Fatalf("Released key is invalid: %v", err)
	return nil, errors.New("Released key is invalid")
}

func main() {
	json_file := "/azure-info.json"
	port := flag.String("keyprovider_sock", "127.0.0.1:50000", "Port on which the key provider to listen")
	flag.Parse()
	lis, err := net.Listen("tcp", *port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("Listening on port %v", port)

	bytes, _ := os.ReadFile(json_file)
	err = json.Unmarshal(bytes, &info)
	if err != nil {
		log.Fatalf("Invalid %v: %v", json_file, string(bytes))
	}
	log.Printf("Read azure info: %v", info)

	s := grpc.NewServer()
	keyprovider.RegisterKeyProviderServiceServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
