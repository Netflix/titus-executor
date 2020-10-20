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
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/metadataserver/identity"
	"github.com/Netflix/titus-executor/metadataserver/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/gogo/protobuf/proto"
	protobuf "github.com/golang/protobuf/proto"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	identTime = 1546292381
)

type testKeyPair struct {
	certType string
	certPem  []byte
	keyPem   []byte
}

// Certs generated with this code that ships with the golang source: https://golang.org/src/crypto/tls/generate_cert.go

var ecdsaCerts = []testKeyPair{
	{
		certType: "ecdsa",
		certPem: []byte(`-----BEGIN CERTIFICATE-----
MIIBczCCARmgAwIBAgIQSEa8X8VpNsHNFXRbTgs8JjAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE5MDEwMTAyMTI1OVoXDTIwMDEwMTAyMTI1OVow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPBC
Bphl7I12gy6tNz1bhFTj470tH+I0Hr2fd7aoaq0Hb4FG7PpSNmDFkpCUretMZ7Q9
upp5GIFXH8fOrAqelZOjUTBPMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMBoGA1UdEQQTMBGCD2Jhci5leGFtcGxlLmNv
bTAKBggqhkjOPQQDAgNIADBFAiEAujE0pPHsYswibcWKNHiAmZBYr+r9It40xkXB
dCvDIZACICWNt2lCy5uUTlO1n7FmrkXTJq2KOuEtqreLwmEsfoOg
-----END CERTIFICATE-----
`),
		keyPem: []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEUnPruwza5Z5kPzHn72Ai4dMHmbkLRsFAmOpPChxvhfoAoGCCqGSM49
AwEHoUQDQgAE8EIGmGXsjXaDLq03PVuEVOPjvS0f4jQevZ93tqhqrQdvgUbs+lI2
YMWSkJSt60xntD26mnkYgVcfx86sCp6Vkw==
-----END EC PRIVATE KEY-----
`),
	},
	{
		certType: "ecdsa",
		certPem: []byte(`-----BEGIN CERTIFICATE-----
MIIBczCCARqgAwIBAgIRAOmCddEG+/qwE8NqUnKhAkowCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEChMHQWNtZSBDbzAeFw0xOTA2MjcwNTE4MDdaFw0yNDA2MjUwNTE4MDda
MBIxEDAOBgNVBAoTB0FjbWUgQ28wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQE
8eITUPx0t8mps1OKTf19EqxJpJhFzKumpa86bDTMIf8nWC/hvccPRsApCkAtEbvE
WAclU1g1IExAikHeXUzMo1EwTzAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYI
KwYBBQUHAwEwDAYDVR0TAQH/BAIwADAaBgNVHREEEzARgg9mb28uZXhhbXBsZS5j
b20wCgYIKoZIzj0EAwIDRwAwRAIgOgqsuNQy9uL6CKeDzsh/A9EC5fSzLpiaP1/x
6WsYStACIF7ijIi0FmX+b5xDvEH2666opC6Lc/yGSGx7xQ19lNVp
-----END CERTIFICATE-----
`),
		keyPem: []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFTZ0SEHFD44YGzXAo1aKAP/X43IuRgmvgah+jGRNcVqoAoGCCqGSM49
AwEHoUQDQgAEBPHiE1D8dLfJqbNTik39fRKsSaSYRcyrpqWvOmw0zCH/J1gv4b3H
D0bAKQpALRG7xFgHJVNYNSBMQIpB3l1MzA==
-----END EC PRIVATE KEY-----
`),
	},
}

var rsaCerts = []testKeyPair{
	{
		certType: "rsa",
		certPem: []byte(`-----BEGIN CERTIFICATE-----
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
`),
		keyPem: []byte(`-----BEGIN RSA PRIVATE KEY-----
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
`),
	},
	{
		certType: "rsa",
		certPem: []byte(`-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIQHf/EE+fCEmgtCgrhVoMyzTANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMB4XDTE5MDYyNzA1MDExNVoXDTI0MDYyNTA1MDEx
NVowEjEQMA4GA1UEChMHQWNtZSBDbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMbErIAJGslndY13s3M1ywihngTvbBn7X/6xxFA4gRcp8mq47E4xP6xX
41/VrEMe3wOcHBZm7TFypkZQ8C9cHqiP7nmLtcCOhaTmq3XU/jOkwsRAjYLwoUOt
fzMXDuHnlqEEqjhUwbL+EQgUL3QgZwIPz3t8Jd4vBcRxbO6pC+vKOjQ0iJ9b9vMq
DSirtz/Tz6q5nKfiSsS6J1bm6uJd/PtivY0l70VIhex6t+hSnfoPXLVRBfVuMHSy
xkhce2sq7xC/0zdn/h8oXx2OA2/4vHc0p2tXwOWOCThGHFVMWMKrI2fjMPIJ4Y7i
qtRTpuxXaCiKY3GS+H3yfcXEuOv1Ix8CAwEAAaNRME8wDgYDVR0PAQH/BAQDAgWg
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwGgYDVR0RBBMwEYIP
Zm9vLmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQB7yUtuaWecUGNNfBkp
OiQ49etX46iW5hoUJMSji75QAOB1WSQ2qMGihiciYn6MIsCRu6ol/ea/Ulu7La8K
+BXoEZFObdHV8KURShSxFQDQA9vwkJxDyRf3TEBG4bK/Z7/7uDLDb2lvOvOiKAD3
FAP8KY3B29T7rpqevjRRFegPtd3KcBgIvrThCQf8PLRU9ybgN15OMj2hiuehLzJM
IvwhRJItZzkcGnblR8iswflVtI0f4JBxCGdCnBVjp7WBbdUica/W5Sf2f8o789On
rqHyjxvN3mD8Dc7O0kfr+/+HdPgUXLvC8GrbgAN+vtWB+7yeUbPzMw6EVVdkCeRh
6j/i
-----END CERTIFICATE-----
`),
		keyPem: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxsSsgAkayWd1jXezczXLCKGeBO9sGftf/rHEUDiBFynyarjs
TjE/rFfjX9WsQx7fA5wcFmbtMXKmRlDwL1weqI/ueYu1wI6FpOarddT+M6TCxECN
gvChQ61/MxcO4eeWoQSqOFTBsv4RCBQvdCBnAg/Pe3wl3i8FxHFs7qkL68o6NDSI
n1v28yoNKKu3P9PPqrmcp+JKxLonVubq4l38+2K9jSXvRUiF7Hq36FKd+g9ctVEF
9W4wdLLGSFx7ayrvEL/TN2f+HyhfHY4Db/i8dzSna1fA5Y4JOEYcVUxYwqsjZ+Mw
8gnhjuKq1FOm7FdoKIpjcZL4ffJ9xcS46/UjHwIDAQABAoIBAAEWvLcq1Zm61lsD
B9mettECSaJPSXFO/jSf9qpV1OcylKBfCPRYsreX96fjvMDVX3VemozI3Y3CygRi
lx47S/OybiT+Te2TGkpP9Sp9EzNnOKXokJ3iAZAkWCkIfE1ifmG9a81JMZJwb9ly
etwQ/V92hLVxdaek7EwqLuWTyXvuKi1QDWI2GNQGm0JKW3K5iN32tKFiX2PrnByV
++iDniVEg4Zkmm8G7kzcu/6Xy5zh1HA8gxMsh0d/9Md6Orzkv+kXY2Z18l4K6aui
pX2dPtOGhscDDinnFdsxKi+tE6r3n0vNADX6VXVYqOdxue1AaGs+AnCPnRHPWSOD
MhUZf9ECgYEAyyUmw2+LEhfQXdv53IaJgB85kzKg33GvoHWAhHJ8ZF81m7FH+LwK
HjkeLuaRokcJFw2y4Ta2PhL+PL/5sUCtckOo5ykUap/Jo6fXRffiB1+7Rgf8rLBk
Xtyqgyjjdz+0BzX0U62ExUTewRcJlS0v6HdzbmJkEHDaLzvHbLKK8ckCgYEA+nv+
THx8uI69UIgns3H+TQzf4XX3ax2PI58DpB7tP44oSdvGjfmm/wYOMn1Ewis4rErz
fhr9gbFnUwdPYfeDVPs6OeQBsXR5Uj6Ua/2gBR8RDZKKBIyyCbbeW/YG8SsMUKmF
UYRPUUk3ykoIM0cdwB6Zrg5uopRI1WmpcRgyoacCgYEAmr8TNz8J/l9bn5QJUt69
cXbXwfSILY4Jjj7UBpC7hy4rxQ0X2TdMsdcq0elbuPVJzGDoCb1GuCR5vMc0qryt
I2S9DlHxtoM/88XQLAF3Eczv+Jnu9ZFs9AI+dak5FUbWmcOU+gUtJaSf1xD4gMWq
P/h2WvjiZs/AtMhh0sBzLVkCgYAfTHEJI6D9+rADKRA05vCMtigfZvskgkwJemwd
DNQ+VcgI+pJD2UcZpKsPegGmdXoeZTsprbuxgfZUNJyhtCjP7Jho9WmUv+YM9c7b
85QUL76UwJPIX8A7YINGYGabqfJe/d+vwOWcVZbICxodNiysfeZcDmeanwa+y/Yl
MI3bDwKBgGswNzeLNSaVXAzHnbvNdU3ijv5RLeyr4MrA4HM4G9nZmcEBGBCdvVD8
nIWkpPRu6QjL3MCv8xQatAjsY8ynXPaGvQiliut5YvWrcbiuh6ccxIdxAOIP+etz
0bC5w179QPOlHNxnTtdCs4mpkDE9Veloi+/LXaSHvDuBz/tkiwHc
-----END RSA PRIVATE KEY-----
`),
	},
}

type stubServer struct {
	reqChan                       chan *http.Request
	fakeEC2MetdataServiceListener net.Listener
	t                             *testing.T
	proxyListener                 net.Listener
	router                        *mux.Router
}

func (s *stubServer) serveHTTP(w http.ResponseWriter, req *http.Request) {
	now := time.Now()
	s.t.Logf("StubServer: %s: %s %s %s", now.Format(time.RFC3339), req.Method, req.Host, req.URL.String())
	select {
	case s.reqChan <- req:
	default:
		s.t.Fatal("Received request, while reqChan blocked")
	}
	w.WriteHeader(200)
	if _, err := w.Write([]byte("Request success!")); err != nil {
		panic(err)
	}
}

// Leaks connections, but this is okay in the time of testing
func setupStubServer(t *testing.T) (*stubServer, error) {
	stubServerInstance := &stubServer{
		reqChan: make(chan *http.Request, 1),
		t:       t,
		router:  mux.NewRouter(),
	}

	stubServerInstance.router.HandleFunc("/latest/api/token", func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("faketoken"))
	})
	stubServerInstance.router.PathPrefix("/").HandlerFunc(stubServerInstance.serveHTTP)

	listener, err := net.Listen("tcp", "0.0.0.0:0") // nolint:gosec
	if err != nil {
		return nil, err
	}
	stubServerInstance.fakeEC2MetdataServiceListener = listener

	listener, err = net.Listen("tcp", "0.0.0.0:0") // nolint:gosec
	if err != nil {
		return nil, err
	}
	stubServerInstance.proxyListener = listener

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		(*stubServerInstance.router).ServeHTTP(writer, request)
	})
	go func() {
		if err := http.Serve(stubServerInstance.fakeEC2MetdataServiceListener, handler); err != nil {
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

func testCertificate(keyPair testKeyPair) (tls.Certificate, error) {
	return tls.X509KeyPair(keyPair.certPem, keyPair.keyPem)
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

func validateTaskIdentityRequest(t *testing.T, keyPair testKeyPair) func(*stubServer, *http.Response) error { // nolint: gocyclo
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

		cert, err := testCertificate(keyPair)
		if err != nil {
			return err
		}
		signature := taskIdentDoc.Signature.Signature
		assert.NotNil(t, signature)

		state := crypto.SHA512.New()
		_, err = state.Write(taskIdentDoc.Identity)
		if err != nil {
			panic(err)
		}
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

func signerFromTestKeyPair(keyPair testKeyPair) *identity.Signer {
	cert, err := testCertificate(keyPair)
	if err != nil {
		panic(err)
	}

	signer, err := identity.NewSigner(cert)
	if err != nil {
		panic(err)
	}

	return signer
}

func setupMetadataServer(t *testing.T, ss *stubServer, keyPair testKeyPair, requireToken bool) *MetadataServer {
	// 8675309 is a fake account ID
	fakeARN := "arn:aws:iam::8675309:role/thisIsAFakeRole"
	fakeTitusTaskInstanceIPAddress := "1.2.3.4"
	fakeTaskIdent := fakeTaskIdentity()

	mdsCfg := types.MetadataServerConfiguration{
		IAMARN:              fakeARN,
		TitusTaskInstanceID: *fakeTaskIdent.Container.RunState.TaskId,
		Ipv4Address:         net.ParseIP(fakeTitusTaskInstanceIPAddress),
		BackingMetadataServer: &url.URL{
			Scheme: "http",
			Host:   ss.fakeEC2MetdataServiceListener.Addr().String(),
		},
		Container:    fakeTaskIdent.Container,
		RequireToken: requireToken,
	}

	if keyPair.certType != "" {
		mdsCfg.Signer = signerFromTestKeyPair(keyPair)
	}

	ms := NewMetaDataServer(context.Background(), mdsCfg)

	// Leaks connections, but this is okay in the time of testing
	go func() {
		if err := http.Serve(ss.proxyListener, ms); err != nil {
			panic(err)
		}
	}()
	t.Log("Metadata server running on: ", ss.proxyListener.Addr().String())
	return ms
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

	setupMetadataServer(t, ss, testKeyPair{}, false)

	tapes :=
		[]vcrTape{
			{makeGetRequest(ss, "/latest/ping"), validateRequestNotProxiedAndSuccess},
			{makeGetRequest(ss, "/nonExistentEndpoint"), validateRequestNotProxiedAndNotFound},
			{makeGetRequest(ss, "/latest/dynamic/instance-identity"), validateRequestProxiedAndSuccess},
			{makeGetRequest(ss, "/latest/user-data"), validateRequestProxiedAndSuccess},
			{makeGetRequest(ss, "/latest/not-allowed-end-point"), validateRequestNotProxiedAndForbidden},
			{makeGetRequest(ss, "/latest/meta-data/placement/availability-zone"), validateRequestProxiedAndSuccess},
			{makeGetRequest(ss, "/latest/meta-data/placement/region"), validateRequestProxiedAndSuccess},
			{makeGetRequest(ss, "/latest/dynamic/instance-identity/signature"), validateRequestNotProxiedAndForbidden},
			{makeGetRequest(ss, "//latest/dynamic/instance-identity/signature"), validateRequestNotProxiedAndForbidden},
			{makeGetRequest(ss, "/latest//dynamic/instance-identity/signature"), validateRequestNotProxiedAndForbidden},
			{makeGetRequest(ss, "/latest/dynamic/./instance-identity/signature"), validateRequestNotProxiedAndForbidden},
			{makeGetRequest(ss, "/latest/../latest/dynamic/instance-identity/signature"), validateRequestNotProxiedAndForbidden},
			{makeGetRequest(ss, "/latest/meta-data/local-ipv4"), validateRequestNotProxiedAndSuccessWithContent("1.2.3.4")},
			{makeGetRequest(ss, "/latest/meta-data/public-ipv4"), validateRequestNotProxiedAndSuccessWithContent("1.2.3.4")},
			{makeGetRequest(ss, "/latest/meta-data/local-hostname"), validateRequestNotProxiedAndSuccessWithContent("1.2.3.4")},
			{makeGetRequest(ss, "/latest/meta-data/public-hostname"), validateRequestNotProxiedAndSuccessWithContent("1.2.3.4")},
			{makeGetRequest(ss, "/latest/meta-data/hostname"), validateRequestNotProxiedAndSuccessWithContent("1.2.3.4")},
			{makeGetRequest(ss, "/latest/meta-data/instance-id"), validateRequestNotProxiedAndSuccessWithContent("e3c16590-0e2f-440d-9797-a68a19f6101e")},
			{makeGetRequest(ss, "/latest/meta-data/iam/security-credentials"), validateRequestNotProxiedAndSuccessWithContent("thisIsAFakeRole")},
			{makeGetRequest(ss, "/latest/meta-data/iam/security-credentials"), validateRequestNotProxiedAndSuccessWithContent("thisIsAFakeRole")},
			{makeGetRequest(ss, "/nflx/v1/task-identity"), validateRequestNotProxiedAndNotFound},
		}
	play(t, ss, tapes)
}

func TestTaskIdentityWithRSA(t *testing.T) {
	rss, err := setupStubServer(t)
	if err != nil {
		t.Fatal("Could not get stub server: ", err)
	}

	ms := setupMetadataServer(t, rss, rsaCerts[0], false)
	tapes :=
		[]vcrTape{
			{makeGetRequest(rss, "/nflx/v1/task-identity"), validateTaskIdentityRequest(t, rsaCerts[0])},
			{makeGetRequestWithHeader(rss, "/nflx/v1/task-identity", "Accept", "application/json"), validateTaskIdentityJSONRequest(t)},
		}
	play(t, rss, tapes)

	// Now set a new key and make sure requests still succeed
	err = ms.SetSigner(signerFromTestKeyPair(rsaCerts[1]))
	assert.Nil(t, err, "no error from SetSigner")
	tapes =
		[]vcrTape{
			{makeGetRequest(rss, "/nflx/v1/task-identity"), validateTaskIdentityRequest(t, rsaCerts[1])},
			{makeGetRequestWithHeader(rss, "/nflx/v1/task-identity", "Accept", "application/json"), validateTaskIdentityJSONRequest(t)},
		}
	play(t, rss, tapes)
}

func TestTaskIdentityWithECDSA(t *testing.T) {
	ess, err := setupStubServer(t)
	if err != nil {
		t.Fatal("Could not get stub server: ", err)
	}

	ms := setupMetadataServer(t, ess, ecdsaCerts[0], false)
	tapes :=
		[]vcrTape{
			{makeGetRequest(ess, "/nflx/v1/task-identity"), validateTaskIdentityRequest(t, ecdsaCerts[0])},
			{makeGetRequestWithHeader(ess, "/nflx/v1/task-identity", "Accept", "application/json"), validateTaskIdentityJSONRequest(t)},
		}
	play(t, ess, tapes)

	// Now set a new key and make sure requests still succeed
	err = ms.SetSigner(signerFromTestKeyPair(ecdsaCerts[1]))
	assert.Nil(t, err, "no error from SetSigner")
	tapes =
		[]vcrTape{
			{makeGetRequest(ess, "/nflx/v1/task-identity"), validateTaskIdentityRequest(t, ecdsaCerts[1])},
			{makeGetRequestWithHeader(ess, "/nflx/v1/task-identity", "Accept", "application/json"), validateTaskIdentityJSONRequest(t)},
		}
	play(t, ess, tapes)
}

func TestTokenWorksWithAWSSDK(t *testing.T) {
	ess, err := setupStubServer(t)
	if err != nil {
		t.Fatal("Could not get stub server: ", err)
	}

	setupMetadataServer(t, ess, ecdsaCerts[0], true)

	url := fmt.Sprintf("http://%s%s", ess.proxyListener.Addr().String(), "/latest")
	endpointConfig := &aws.Config{Endpoint: &url}
	client := ec2metadata.New(session.Must(session.NewSession(endpointConfig)))

	got, err := client.GetMetadata("instance-id")
	assert.Nil(t, err)

	expected := fakeTaskIdentity().GetTask().GetTaskId()
	assert.Equal(t, expected, got)
}

func TestRequireToken(t *testing.T) {
	ess, err := setupStubServer(t)
	if err != nil {
		t.Fatal("Could not get stub server: ", err)
	}

	ms := setupMetadataServer(t, ess, ecdsaCerts[0], true)

	// Get Token
	tokenPath := fmt.Sprintf("http://%s%s", ess.proxyListener.Addr().String(), "/latest/api/token")
	req, err := http.NewRequest("PUT", tokenPath, strings.NewReader(""))
	assert.Nil(t, err)
	req.Header.Add("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "20")

	w := httptest.NewRecorder()
	ms.ServeHTTP(w, req)
	assert.Equal(t, w.Header().Get("X-Aws-Ec2-Metadata-Token-Ttl-Seconds"), "20")
	token := w.Body.String()

	instancePath := fmt.Sprintf("http://%s%s", ess.proxyListener.Addr().String(), "/latest/meta-data/instance-id")
	req, err = http.NewRequest("GET", instancePath, nil)
	assert.Nil(t, err)
	req.Header.Add("X-aws-ec2-metadata-token", token)

	w = httptest.NewRecorder()
	ms.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestNoTokenReturns401(t *testing.T) {
	ess, err := setupStubServer(t)
	if err != nil {
		t.Fatal("Could not get stub server: ", err)
	}

	ms := setupMetadataServer(t, ess, ecdsaCerts[0], true)

	fullPath := fmt.Sprintf("http://%s%s", ess.proxyListener.Addr().String(), "/latest/meta-data/instance-id")
	req, err := http.NewRequest("GET", fullPath, nil)
	assert.Nil(t, err)

	w := httptest.NewRecorder()
	ms.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestInvalidTokenReturns401(t *testing.T) {
	ess, err := setupStubServer(t)
	if err != nil {
		t.Fatal("Could not get stub server: ", err)
	}

	ms := setupMetadataServer(t, ess, ecdsaCerts[0], true)

	fullPath := fmt.Sprintf("http://%s%s", ess.proxyListener.Addr().String(), "/latest/meta-data/instance-id")
	req, err := http.NewRequest("GET", fullPath, nil)
	assert.Nil(t, err)
	req.Header.Add("X-aws-ec2-metadata-token", "invalid-token")

	w := httptest.NewRecorder()
	ms.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestXForwardedForAllowedByDefault(t *testing.T) {
	ess, err := setupStubServer(t)
	if err != nil {
		t.Fatal("Could not get stub server: ", err)
	}

	ms := setupMetadataServer(t, ess, ecdsaCerts[0], true)

	// Get Token
	tokenPath := fmt.Sprintf("http://%s%s", ess.proxyListener.Addr().String(), "/latest/api/token")
	req, err := http.NewRequest("PUT", tokenPath, strings.NewReader(""))
	assert.Nil(t, err)
	req.Header.Add("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "20")
	req.Header.Add("X-Forwarded-For", "someone")

	w := httptest.NewRecorder()
	ms.ServeHTTP(w, req)
	token := w.Body.String()

	assert.Greater(t, len(token), 0)
}

func TestXForwardedForBlockingMode(t *testing.T) {
	ess, err := setupStubServer(t)
	if err != nil {
		t.Fatal("Could not get stub server: ", err)
	}

	ms := setupMetadataServer(t, ess, ecdsaCerts[0], true)
	ms.xForwardedForBlockingMode = true

	// Get Token
	tokenPath := fmt.Sprintf("http://%s%s", ess.proxyListener.Addr().String(), "/latest/api/token")
	req, err := http.NewRequest("PUT", tokenPath, strings.NewReader(""))
	assert.Nil(t, err)
	req.Header.Add("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "20")
	req.Header.Add("X-Forwarded-For", "someone")

	w := httptest.NewRecorder()
	ms.ServeHTTP(w, req)

	assert.Equal(t, w.Code, http.StatusForbidden)
}

func TestInstanceMetadataDocument(t *testing.T) {
	ess, err := setupStubServer(t)
	if err != nil {
		t.Fatal("Could not get stub server: ", err)
	}

	oldRouter := ess.router
	router := mux.NewRouter()
	ess.router = router
	router.HandleFunc("/latest/meta-data/placement/availability-zone", func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("us-east-1a"))
	})
	router.HandleFunc("/latest/meta-data/placement/region", func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("us-east-1"))
	})
	router.PathPrefix("/").Handler(oldRouter)

	setupMetadataServer(t, ess, ecdsaCerts[0], true)

	url := fmt.Sprintf("http://%s%s", ess.proxyListener.Addr().String(), "/latest")
	endpointConfig := &aws.Config{Endpoint: &url}
	client := ec2metadata.New(session.Must(session.NewSession(endpointConfig)))
	doc, err := client.GetInstanceIdentityDocument()
	require.Nil(t, err)
	assert.Equal(t, "us-east-1", doc.Region)
}
