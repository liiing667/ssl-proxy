package reverseproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateRequestFraming(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*http.Request)
		wantErr bool
	}{
		{
			name:    "no body and no framing headers",
			mutate:  func(req *http.Request) {},
			wantErr: false,
		},
		{
			name: "single content length",
			mutate: func(req *http.Request) {
				req.Header.Set("Content-Length", "5")
				req.ContentLength = 5
			},
			wantErr: false,
		},
		{
			name: "duplicate identical content length",
			mutate: func(req *http.Request) {
				req.Header.Add("Content-Length", "5")
				req.Header.Add("Content-Length", "5")
				req.ContentLength = 5
			},
			wantErr: false,
		},
		{
			name: "duplicate conflicting content length",
			mutate: func(req *http.Request) {
				req.Header.Add("Content-Length", "5")
				req.Header.Add("Content-Length", "6")
			},
			wantErr: true,
		},
		{
			name: "non numeric content length",
			mutate: func(req *http.Request) {
				req.Header.Set("Content-Length", "abc")
			},
			wantErr: true,
		},
		{
			name: "single chunked transfer encoding",
			mutate: func(req *http.Request) {
				req.Header.Set("Transfer-Encoding", "chunked")
				req.TransferEncoding = []string{"chunked"}
				req.ContentLength = -1
			},
			wantErr: false,
		},
		{
			name: "multiple transfer encoding fields",
			mutate: func(req *http.Request) {
				req.Header.Add("Transfer-Encoding", "chunked")
				req.Header.Add("Transfer-Encoding", "chunked")
			},
			wantErr: true,
		},
		{
			name: "transfer encoding stack",
			mutate: func(req *http.Request) {
				req.Header.Set("Transfer-Encoding", "chunked, identity")
			},
			wantErr: true,
		},
		{
			name: "unsupported transfer coding",
			mutate: func(req *http.Request) {
				req.Header.Set("Transfer-Encoding", "gzip")
			},
			wantErr: true,
		},
		{
			name: "content length and transfer encoding together",
			mutate: func(req *http.Request) {
				req.Header.Set("Content-Length", "5")
				req.Header.Set("Transfer-Encoding", "chunked")
				req.TransferEncoding = []string{"chunked"}
				req.ContentLength = -1
			},
			wantErr: true,
		},
		{
			name: "parsed chunked framing with raw transfer encoding header",
			mutate: func(req *http.Request) {
				req.Header.Set("Transfer-Encoding", "chunked")
				req.TransferEncoding = []string{"chunked"}
				req.ContentLength = -1
			},
			wantErr: false,
		},
		{
			name: "unsupported parsed transfer coding",
			mutate: func(req *http.Request) {
				req.TransferEncoding = []string{"gzip"}
				req.ContentLength = -1
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
			tc.mutate(req)
			err := validateRequestFraming(req)
			if tc.wantErr && err == nil {
				t.Fatalf("validateRequestFraming: got nil error, want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateRequestFraming: got error %v, want nil", err)
			}
		})
	}
}
