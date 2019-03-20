package metadataserver

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/metadataserver/types"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/metadataserver/identity"
	"github.com/gogo/protobuf/proto"
	protobuf "github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
)

const (
	identTime = 1546292381
)

type stubServerHandler struct {
	server *stubServer
}

func (s *stubServerHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	now := time.Now()
	s.server.t.Logf("%s: %s %s %s", now.Format(time.RFC3339), req.Method, req.Host, req.URL.String())
	select {
	case s.server.reqChan <- req:
	default:
		s.server.t.Fatal("Received request, while reqChan blocked")
	}
	w.WriteHeader(200)
	if _, err := w.Write([]byte("Request success!")); err != nil {
		panic(err)
	}
}

type stubServer struct {
	reqChan                       chan *http.Request
	fakeEC2MetdataServiceListener net.Listener
	t                             *testing.T
	proxyListener                 net.Listener
}

// Leaks connections, but this is okay in the time of testing
func setupStubServer(t *testing.T) (*stubServer, error) {
	stubServerInstance := &stubServer{
		reqChan: make(chan *http.Request, 1),
		t:       t,
	}

	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	stubServerInstance.fakeEC2MetdataServiceListener = listener

	listener, err = net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	stubServerInstance.proxyListener = listener

	go func() {
		if err := http.Serve(stubServerInstance.fakeEC2MetdataServiceListener, &stubServerHandler{stubServerInstance}); err != nil {
			panic(err)
		}
	}()

	t.Log("Stub server listening on: ", stubServerInstance.fakeEC2MetdataServiceListener.Addr().String())
	return stubServerInstance, nil
}

type vcrTape struct {
	request           *http.Request
	responseValidator func(*stubServer, *http.Response) error
}

func makeGetRequest(ss *stubServer, path string) *http.Request {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	fullPath := fmt.Sprintf("http://%s%s", ss.proxyListener.Addr().String(), path)
	if req, err := http.NewRequest("GET", fullPath, nil); err != nil {
		panic(err)
	} else {
		return req
	}
}

func makeGetRequestWithHeader(ss *stubServer, path string, headerName string, headerVal string) *http.Request {
	req := makeGetRequest(ss, path)
	req.Header.Add(headerName, headerVal)
	return req
}

func fakeTaskIdentity() *titus.TaskIdentity {
	taskID := "e3c16590-0e2f-440d-9797-a68a19f6101e"
	ipAddr := "1.2.3.4"
	entrypoint := "/usr/bin/sleep 10"
	taskStatus := titus.TaskInfo_RUNNING
	launchTime := uint64(identTime)

	taskInfo := &titus.TaskInfo{
		ContainerId: &taskID,
		TaskId:      &taskID,
		HostName:    &taskID,
		Status:      &taskStatus,
	}
	taskIdent := &titus.TaskIdentity{
		Container: &titus.ContainerInfo{
			EntrypointStr: &entrypoint,
			Process: &titus.ContainerInfo_Process{
				Entrypoint: []string{entrypoint},
			},
			ImageName: protobuf.String("titusoss/alpine"),
			Version:   protobuf.String("latest"),
			RunState: &titus.RunningContainerInfo{
				HostName:          &taskID,
				LaunchTimeUnixSec: &launchTime,
				TaskId:            &taskID,
			},
		},
		Ipv4Address: &ipAddr,
		Task:        taskInfo,
	}

	return taskIdent
}

func testCertificate(certType string) (tls.Certificate, error) {
	// Certs generated with this code that ships with the golang source: https://golang.org/src/crypto/tls/generate_cert.go
	var certPem []byte
	var keyPem []byte

	switch certType {
	case "ecdsa":
		certPem = []byte(`-----BEGIN CERTIFICATE-----
MIIBczCCARmgAwIBAgIQSEa8X8VpNsHNFXRbTgs8JjAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE5MDEwMTAyMTI1OVoXDTIwMDEwMTAyMTI1OVow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPBC
Bphl7I12gy6tNz1bhFTj470tH+I0Hr2fd7aoaq0Hb4FG7PpSNmDFkpCUretMZ7Q9
upp5GIFXH8fOrAqelZOjUTBPMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMBoGA1UdEQQTMBGCD2Jhci5leGFtcGxlLmNv
bTAKBggqhkjOPQQDAgNIADBFAiEAujE0pPHsYswibcWKNHiAmZBYr+r9It40xkXB
dCvDIZACICWNt2lCy5uUTlO1n7FmrkXTJq2KOuEtqreLwmEsfoOg
-----END CERTIFICATE-----
`)
		keyPem = []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEUnPruwza5Z5kPzHn72Ai4dMHmbkLRsFAmOpPChxvhfoAoGCCqGSM49
AwEHoUQDQgAE8EIGmGXsjXaDLq03PVuEVOPjvS0f4jQevZ93tqhqrQdvgUbs+lI2
YMWSkJSt60xntD26mnkYgVcfx86sCp6Vkw==
-----END EC PRIVATE KEY-----
`)

	case "rsa":
		certPem = []byte(`-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIQdH5TuK8mvP9KJ2lxc9XhejANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMB4XDTE5MDEwMTAxMzgxN1oXDTIwMDEwMTAxMzgx
N1owEjEQMA4GA1UEChMHQWNtZSBDbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMCmX9H/sVCYAQYQrXxrYOJSaSzgRcCEbrBr7p7lmZ5veSUY5Yk8ubkL
TCbZzU6fvFu7dQ4jvsYX2cWuKHVnjVQkeqPwP2D3CSswAfp/yNzk6iN3SVEB58za
dC1M3su81M+wweWeSNi5aAV3bNYzJXJRdQQNGxMsl634zXScNuNQdViwANxee4ky
0YO7N0YsQ1S3nnD5aywbX0QYdB/KAE2YvEUwz//3KanxKJRtJFcSSVLiAV0uR5Bw
7BtzM/40qh5bok3nKxAiIYkTGKZVNYKNzWxHNI/ShXVXokiZYInovp73XXokYH1E
eSapxCPVIf7TlbCzYZ/BM9SyPRNi//kCAwEAAaNRME8wDgYDVR0PAQH/BAQDAgWg
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwGgYDVR0RBBMwEYIP
Zm9vLmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQAjc7f8jgtv6PvFS+At
eZveC1j8aWVNUIHv+DXReBcYMJ0PtjT/jGfcnWjse2cwXTLu01qFPlcDPEwJbJVK
jWszo+K7TNbHF1obnB1FxYOsIModBEWd+Zcj+y6YHp1FUxizn6M1bxGsJ0lz5tq7
oC5gcLU81mcce6/PoFVyUgpkIuTZ2BK9iG5FgDZsTGwR3UtCTyuwuFtCu2DKyqrD
1RL0sxGEWskv6oIyHgqczttVzl6Cyb8PRcUrnY+Au6Qtfst2L0SOlrkI67UIDwOk
Gp2zUWhIylqxOVL6lmzMqQR4RTZMlRW7XqHugjsKcpz7YJdAYUM2KeQb9yjKcJtR
E3Ui
-----END CERTIFICATE-----
`)
		keyPem = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAwKZf0f+xUJgBBhCtfGtg4lJpLOBFwIRusGvunuWZnm95JRjl
iTy5uQtMJtnNTp+8W7t1DiO+xhfZxa4odWeNVCR6o/A/YPcJKzAB+n/I3OTqI3dJ
UQHnzNp0LUzey7zUz7DB5Z5I2LloBXds1jMlclF1BA0bEyyXrfjNdJw241B1WLAA
3F57iTLRg7s3RixDVLeecPlrLBtfRBh0H8oATZi8RTDP//cpqfEolG0kVxJJUuIB
XS5HkHDsG3Mz/jSqHluiTecrECIhiRMYplU1go3NbEc0j9KFdVeiSJlgiei+nvdd
eiRgfUR5JqnEI9Uh/tOVsLNhn8Ez1LI9E2L/+QIDAQABAoIBAQCfk7DfdFteFOsU
KRBrdU6lafow7/0XQRunC2B3QlyDPncs4XiQuzpkKxWDQPqtW+dcXOTTN4y47dy3
wFFHHuWUgzsLPOBi4342xed9pget4fiINDEI5vkpWPLO61PJk7r75sBWAUz6KGof
zRLcQzWLginZlzmMIm3p76PQKe3VT8gEVKGmlF2QGUXC+UTn1rrW9kNm9baNQWgt
hJU70KyChJ+db+0WDdwlMrfI3K+U8GoeF98uIjDV2mypgvyKvokqX8aFgpgkn2Qk
FzbCfN/swaPckHJ5nj5oSE6Gl2glJeSAXfN6rvvZ9cvi8Os4c89X8YNL+GA0AUvZ
U4tYE/NZAoGBAPiRPW8wvyTjV4n1uKHxwHByssJ9QyL8v35KZ2lRhN9+PxMNJVmu
qK+DjnbcmT+MC6KXgcDCOSQSPrEZHVAaiIIwu99Qc3ibkEA6DMI+iXKHFq+D21Ch
N1bwAXqicOOzSzqWv3ihunINwabHMabN/ry/l1xX2g6BpY5rj7JF1kI/AoGBAMZp
F2nTbs2bBnUsgvJuvw3GWeH5FS8v1xESYTXPx44k4SKG52mTYR9Rv2RfQQYbZF4P
QpMj/cEmcuGWzuy8xZMJra2rMb55jUiKCnbq1t67SSnbT2b5McPxLFwmb8vEqFEG
cW1OosXPPiH2Tcj9+ll1cZKD4vQVbu/I59F+eD/HAoGACRZmRJZnppWZMbYGFgWc
n3/SAUJLHhBXf+qAdV1BmlonPC8S2oCEMkaBAt91ytj34+3eFIoFRMhV+muMos0V
iIz3kWaDkjk9wNtedAuNQt6lea08a2o5d7g2laEyt2Bqs62nOmXPRzQxjENkEVEe
qw/mHL4pfrZGszpDeqUK/EkCgYEAjTQjjpQDql3m5aMs+j4oyDPeqfyrv+5LIAI1
nqdl/NpwQzNBJBjYKQLztAo6a485CdvQZIlbwYeMgNHkKAVckv1zVkKc31MAYpyj
P+h3zQH62sgSpVU5vpo4GMjeDWXC6A8u0D0DiMWqEV+KEj32Wo5DqqMj9NQAJLSV
jrlz+OcCgYEA8OeYVN/1VshldJ+OfIqL8GxArHFC7Lu4mpeuT7sZ7ktlaDH4I3ef
k4CPcd9/5MB2WTkn/1ucYrgta892ABosTz6KdFu2cxmjvahkuQPKGFxf76oor7cU
jJIO2m+Mu6C35Z4BvSJ+m71ULKZBaAbYslaM9eBUPq248GLfGmGgopk=
-----END RSA PRIVATE KEY-----
`)
	default:
		return tls.Certificate{}, fmt.Errorf("Unknown cert type %s", certType)
	}

	return tls.X509KeyPair(certPem, keyPem)
}

func validateRequestNotProxied(ss *stubServer, resp *http.Response) error {
	select {
	case req := <-ss.reqChan:
		return fmt.Errorf("Saw request %+v when none was intended", req)
	default:
		return nil
	}
}

func validateRequestProxied(ss *stubServer, resp *http.Response) error {
	select {
	case <-ss.reqChan:
		return nil
	default:
		return fmt.Errorf("Did not see request")
	}
}

func validateRequestProxiedAndSuccess(ss *stubServer, resp *http.Response) error {
	if err := validateRequestProxied(ss, resp); err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Response status code not 200, instead: %d", resp.StatusCode)
	}
	return nil
}

func validateRequestNotProxiedAndForbidden(ss *stubServer, resp *http.Response) error {
	if err := validateRequestNotProxied(ss, resp); err != nil {
		return err
	}
	if resp.StatusCode != 403 {
		return fmt.Errorf("Response status code not 403, instead: %d", resp.StatusCode)
	}
	return nil
}

func validateRequestNotProxiedAndNotFound(ss *stubServer, resp *http.Response) error {
	if err := validateRequestNotProxied(ss, resp); err != nil {
		return err
	}
	if resp.StatusCode != 404 {
		return fmt.Errorf("Response status code not 404, instead: %d", resp.StatusCode)
	}
	return nil
}

func validateRequestNotProxiedAndSuccess(ss *stubServer, resp *http.Response) error {
	if err := validateRequestNotProxied(ss, resp); err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Response status code not 200, instead: %d", resp.StatusCode)
	}
	return nil
}

func validateRequestNotProxiedAndSuccessWithContent(substr string) func(*stubServer, *http.Response) error {
	return func(ss *stubServer, resp *http.Response) error {
		if err := validateRequestNotProxiedAndSuccess(ss, resp); err != nil {
			return err
		}
		if content, err := ioutil.ReadAll(resp.Body); err != nil {
			return err
		} else if !strings.Contains(string(content), substr) {
			return fmt.Errorf("Content '%s' does not contain string '%s'", string(content), substr)
		}
		return nil
	}
}

func validateTaskIdentityRequest(t *testing.T, certType string) func(*stubServer, *http.Response) error { // nolint: gocyclo
	return func(ss *stubServer, resp *http.Response) error {
		if err := validateRequestNotProxiedAndSuccess(ss, resp); err != nil {
			return err
		}

		content, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		taskIdentDoc := new(titus.TaskIdentityDocument)
		err = proto.Unmarshal(content, taskIdentDoc)
		if err != nil {
			return err
		}

		assert.NotNil(t, taskIdentDoc.Signature)
		assert.NotNil(t, taskIdentDoc.Identity)

		// Identity

		taskIdent := new(titus.TaskIdentity)
		err = proto.Unmarshal(taskIdentDoc.Identity, taskIdent)
		if err != nil {
			return err
		}
		expectedTaskIdent := fakeTaskIdentity()
		assert.NotNil(t, taskIdent.UnixTimestampSec)
		expectedTaskIdent.UnixTimestampSec = taskIdent.UnixTimestampSec
		assert.Equal(t, *expectedTaskIdent, *taskIdent)
		// The identity server checks Process for entrypoint and command:
		assert.NotNil(t, taskIdent.Container.Process)
		assert.Equal(t, []string{*expectedTaskIdent.Container.EntrypointStr}, taskIdent.Container.Process.Entrypoint)

		// Signature

		cert, err := testCertificate(certType)
		if err != nil {
			return err
		}
		signature := taskIdentDoc.Signature.Signature
		assert.NotNil(t, signature)

		state := crypto.SHA512.New()
		state.Write(taskIdentDoc.Identity)
		hash := state.Sum(nil)

		switch k := cert.PrivateKey.(type) {
		case *ecdsa.PrivateKey:
			var ecdsaSignature struct {
				R, S *big.Int
			}
			_, mErr := asn1.Unmarshal(signature, &ecdsaSignature)
			if mErr != nil {
				return mErr
			}

			isValid := ecdsa.Verify(&k.PublicKey, hash, ecdsaSignature.R, ecdsaSignature.S)
			if !isValid {
				return errors.New("ecdsa verify failed")
			}

			assert.Equal(t, titus.SignatureAlgorithm_SHA512withECDSA, *taskIdentDoc.Signature.Algorithm)

		case *rsa.PrivateKey:
			vErr := rsa.VerifyPSS(&k.PublicKey, crypto.SHA512, hash, signature, &rsa.PSSOptions{SaltLength: 20})
			if vErr != nil {
				return vErr
			}
			assert.Equal(t, titus.SignatureAlgorithm_SHA512withRSAandMGF1, *taskIdentDoc.Signature.Algorithm)

		default:
			return fmt.Errorf("unexpected private key type: %T", k)
		}

		assert.Equal(t, 1, len(taskIdentDoc.Signature.CertChain))
		assert.Equal(t, cert.Certificate, taskIdentDoc.Signature.CertChain)

		return nil
	}
}

func validateTaskIdentityJSONRequest(t *testing.T) func(*stubServer, *http.Response) error {
	return func(ss *stubServer, resp *http.Response) error {
		if err := validateRequestNotProxiedAndSuccess(ss, resp); err != nil {
			return err
		}

		contents, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		var taskIdentDoc titus.TaskIdentityStringDocument
		if err = json.Unmarshal(contents, &taskIdentDoc); err != nil {
			return err
		}

		assert.NotNil(t, taskIdentDoc.Identity)
		assert.NotNil(t, taskIdentDoc.Identity.Container)
		assert.NotNil(t, taskIdentDoc.Identity.Ipv4Address)
		assert.NotNil(t, taskIdentDoc.Identity.Task)
		assert.NotNil(t, taskIdentDoc.Identity.UnixTimestampSec)

		expectedTaskIdent := fakeTaskIdentity()
		expectedTaskIdent.UnixTimestampSec = taskIdentDoc.Identity.UnixTimestampSec
		assert.Equal(t, *expectedTaskIdent, *taskIdentDoc.Identity)

		return nil
	}
}

func setupMetadataServer(t *testing.T, ss *stubServer, certType string) {
	// 8675309 is a fake account ID
	fakeARN := "arn:aws:iam::8675309:role/thisIsAFakeRole"
	fakeTitusTaskInstanceIPAddress := "1.2.3.4"
	fakeTaskIdent := fakeTaskIdentity()

	mdsCfg := types.MetadataServerConfiguration{
		IAMARN:              fakeARN,
		TitusTaskInstanceID: *fakeTaskIdent.Container.RunState.TaskId,
		Ipv4Address:         net.ParseIP(fakeTitusTaskInstanceIPAddress),
		VpcID:               "vpc-1234",
		EniID:               "eni-1234",
		BackingMetadataServer: &url.URL{
			Scheme: "http",
			Host:   ss.fakeEC2MetdataServiceListener.Addr().String(),
		},
		Container: fakeTaskIdent.Container,
	}

	if certType != "none" {
		cert, err := testCertificate(certType)
		if err != nil {
			panic(err)
		}

		mdsCfg.Signer, err = identity.NewSigner(cert)
		if err != nil {
			panic(err)
		}
	}

	ms := NewMetaDataServer(context.Background(), mdsCfg)

	// Leaks connections, but this is okay in the time of testing
	go func() {
		if err := http.Serve(ss.proxyListener, ms); err != nil {
			panic(err)
		}
	}()
	t.Log("Metadata server running on: ", ss.proxyListener.Addr().String())
}

func play(t *testing.T, ss *stubServer, tapes []vcrTape) {
	for _, tape := range tapes {
		client := http.Client{}
		if resp, err := client.Do(tape.request); err != nil {
			t.Fatal("Unexpected error: ", err)
		} else {
			if err2 := tape.responseValidator(ss, resp); err2 != nil {
				t.Fatalf("Request %+v resulted in error %+v", tape.request, err2)
			}
		}
	}
}

func TestVCR(t *testing.T) {
	ss, err := setupStubServer(t)
	if err != nil {
		t.Fatal("Could not get stub server: ", err)
	}

	setupMetadataServer(t, ss, "none")

	tapes :=
		[]vcrTape{
			{makeGetRequest(ss, "/latest/ping"), validateRequestNotProxiedAndSuccess},
			{makeGetRequest(ss, "/nonExistentEndpoint"), validateRequestNotProxiedAndNotFound},
			{makeGetRequest(ss, "/latest/dynamic/instance-identity"), validateRequestProxiedAndSuccess},
			{makeGetRequest(ss, "/latest/user-data"), validateRequestProxiedAndSuccess},
			{makeGetRequest(ss, "/latest/not-allowed-end-point"), validateRequestNotProxiedAndForbidden},
			{makeGetRequest(ss, "/latest/dynamic/instance-identity/signature"), validateRequestNotProxiedAndForbidden},
			{makeGetRequest(ss, "//latest/dynamic/instance-identity/signature"), validateRequestNotProxiedAndForbidden},
			{makeGetRequest(ss, "/latest//dynamic/instance-identity/signature"), validateRequestNotProxiedAndForbidden},
			{makeGetRequest(ss, "/latest/dynamic/./instance-identity/signature"), validateRequestNotProxiedAndForbidden},
			{makeGetRequest(ss, "/latest/../latest/dynamic/instance-identity/signature"), validateRequestNotProxiedAndForbidden},
			{makeGetRequest(ss, "/latest/meta-data/local-ipv4"), validateRequestNotProxiedAndSuccessWithContent("1.2.3.4")},
			{makeGetRequest(ss, "/latest/meta-data/public-ipv4"), validateRequestNotProxiedAndSuccessWithContent("1.2.3.4")},
			{makeGetRequest(ss, "/latest/meta-data/local-hostname"), validateRequestNotProxiedAndSuccessWithContent("1.2.3.4")},
			{makeGetRequest(ss, "/latest/meta-data/public-hostname"), validateRequestNotProxiedAndSuccessWithContent("1.2.3.4")},
			{makeGetRequest(ss, "/latest/meta-data/instance-id"), validateRequestNotProxiedAndSuccessWithContent("e3c16590-0e2f-440d-9797-a68a19f6101e")},
			{makeGetRequest(ss, "/latest/meta-data/iam/security-credentials"), validateRequestNotProxiedAndSuccessWithContent("thisIsAFakeRole")},
			{makeGetRequest(ss, "/latest/meta-data/iam/security-credentials"), validateRequestNotProxiedAndSuccessWithContent("thisIsAFakeRole")},
			{makeGetRequest(ss, "/nflx/v1/task-identity"), validateRequestNotProxiedAndNotFound},
		}
	play(t, ss, tapes)

	rss, err := setupStubServer(t)
	if err != nil {
		t.Fatal("Could not get stub server: ", err)
	}

	setupMetadataServer(t, rss, "rsa")
	tapes =
		[]vcrTape{
			{makeGetRequest(rss, "/nflx/v1/task-identity"), validateTaskIdentityRequest(t, "rsa")},
			{makeGetRequestWithHeader(rss, "/nflx/v1/task-identity", "Accept", "application/json"), validateTaskIdentityJSONRequest(t)},
		}
	play(t, rss, tapes)

	ess, err := setupStubServer(t)
	if err != nil {
		t.Fatal("Could not get stub server: ", err)
	}

	setupMetadataServer(t, ess, "ecdsa")
	tapes =
		[]vcrTape{
			{makeGetRequest(ess, "/nflx/v1/task-identity"), validateTaskIdentityRequest(t, "ecdsa")},
			{makeGetRequestWithHeader(ess, "/nflx/v1/task-identity", "Accept", "application/json"), validateTaskIdentityJSONRequest(t)},
		}
	play(t, ess, tapes)
}
