package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
)

const (
	// keyFileName is the name of the file where the private key will be saved
	keyFileName = "private.pem"
	// certFileName is the name of the file where the self-signed certificate will be saved
	certFileName = "cert.pem"
)

func main() {

	// Create a private key and a self-signed certificate
	err := CreateSelfSignedKeyAndCertFiles(keyFileName, certFileName)
	if err != nil {
		log.Fatalf("Failed to create key and cert files: %v", err)
	}

	// Create a new TLS configuration
	cfg := &tls.Config{
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{},
	}

	// Create a new HTTP server mux
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	// Set an HTTP server instance with configuration with the TLS configuration
	srv := &http.Server{
		Addr:         ":443",
		Handler:      mux,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	// Start the server
	fmt.Printf("Starting server on %s\n", srv.Addr)
	log.Fatal(srv.ListenAndServeTLS(certFileName, keyFileName))
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("This is an example server.\n"))

	// Get the curve ID from the writer
	response := ""

	curveID, err := getRequestCurveID(r)
	if err != nil {
		w.Write([]byte("Failed to get curve ID from the request\n"))
		return
	} else {
		curveName, err := getTlsCurveIDName(curveID)
		if err != nil {
			w.Write([]byte("Failed to get curve name from the curve ID\n"))
			return
		}
		response = fmt.Sprintf("TLS Connection: Curve ID: 0x%x, Name: %v\n", uint16(curveID), curveName)
	}

	// Get the cipher suite ID from the request
	cipherSuiteID := r.TLS.CipherSuite
	cipherSuiteName := tls.CipherSuiteName(cipherSuiteID)

	response += fmt.Sprintf("TLS Connection:	Cipher Suite: 0x%d , Name:%s\n", cipherSuiteID, cipherSuiteName)

	w.Write([]byte(response))
}
