package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCreate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut || request.URL.Path != "/1K7mQ2xR8VpC" || request.Header.Get("Content-Type") != ContentType {
			t.Fatalf("unexpected request %s %s", request.Method, request.Header.Get("Content-Type"))
		}
		if request.Header.Get("X-Wipe-Cipher-Version") != "1" || request.Header.Get("X-Wipe-Client") != "cli" || request.Header.Get("X-Wipe-On-Read") != "1" || request.Header.Get("X-Wipe-Deletion-Key") == "" || request.Header.Get("X-Wipe-Content-Hash") == "" {
			t.Fatalf("missing protocol headers: %#v", request.Header)
		}
		body, _ := io.ReadAll(request.Body)
		if string(body) != "encrypted" {
			t.Fatalf("unexpected body %q", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"id":"1K7mQ2xR8VpC","created":true}`))
	}))
	defer server.Close()

	client := Client{Endpoint: server.URL, HTTPClient: server.Client(), UserAgent: "wipeme/test"}
	response, err := client.Create(context.Background(), "1K7mQ2xR8VpC", bytes.NewReader([]byte("encrypted")), 9, time.Now().Add(time.Hour), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if response.MessageID != "1K7mQ2xR8VpC" {
		t.Fatalf("unexpected response %#v", response)
	}
}

func TestCreateReturnsAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = writer.Write([]byte(`{"error":"message is too large"}`))
	}))
	defer server.Close()
	client := Client{Endpoint: server.URL, HTTPClient: server.Client()}
	_, err := client.Create(context.Background(), "1K7mQ2xR8VpC", bytes.NewReader(nil), 0, time.Now().Add(time.Hour), bytes.Repeat([]byte{7}, 32))
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("message is too large")) {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestDelete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodDelete || request.URL.Path != "/1K7mQ2xR8VpC" {
			t.Fatalf("unexpected deletion request %s %s", request.Method, request.URL.Path)
		}
		if request.Header.Get("X-Wipe-Deletion-Key") == "" {
			t.Fatal("missing deletion key")
		}
		_, _ = writer.Write([]byte(`{"deleted":true}`))
	}))
	defer server.Close()
	client := Client{Endpoint: server.URL, HTTPClient: server.Client()}
	if err := client.Delete(context.Background(), "1K7mQ2xR8VpC", bytes.Repeat([]byte{8}, 32)); err != nil {
		t.Fatal(err)
	}
}
