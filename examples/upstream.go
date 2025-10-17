package main

import (
    "encoding/base64"
    "encoding/json"
    "net/http"
)

type ClientTLSInfo struct {
    Subject    string   `json:"subject"`
    URISANs    []string `json:"uri_sans"`
    DNSSANs    []string `json:"dns_sans"`
    Hash       string   `json:"hash"`
    NotBefore  string   `json:"not_before"`
    NotAfter   string   `json:"not_after"`
    Serial     string   `json:"serial"`
}

func index_handler(w http.ResponseWriter, r *http.Request) {
    if header := r.Header.Get("X-Client-TLS-Info"); header != "" {
        var info ClientTLSInfo
        decoded, _ := base64.StdEncoding.DecodeString(header)
        _ = json.Unmarshal(decoded, &info)
        _, _ = w.Write([]byte("Client Subject: " + info.Subject))
        return
    }
    w.WriteHeader(http.StatusUnauthorized)
}

func main() {
    server := &http.Server{}
    http.HandleFunc("/", index_handler)
    server.Addr = ":8080"
    _ = server.ListenAndServe()
}
