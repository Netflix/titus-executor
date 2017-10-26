package metadataserver

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
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

func setupMetadataServer(t *testing.T, ss *stubServer) {
	// 8675309 is a fake account ID
	fakeARN := "arn:aws:iam::8675309:role/thisIsAFakeRole"
	fakeTitusTaskInstanceID := "e3c16590-0e2f-440d-9797-a68a19f6101e"
	fakeTitusTaskInstanceIPAddress := "1.2.3.4"
	fakeEC2MetadataURI := "http://" + ss.fakeEC2MetdataServiceListener.Addr().String()
	ms := NewMetaDataServer(context.Background(), fakeEC2MetadataURI, fakeARN, fakeTitusTaskInstanceID, fakeTitusTaskInstanceIPAddress)

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

	setupMetadataServer(t, ss)

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
		}
	play(t, ss, tapes)
}
