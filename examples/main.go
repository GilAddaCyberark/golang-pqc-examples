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

	// Create a new HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {

		w.Write([]byte("This is an example server.\n"))

		// Get the curve ID from the writer
		curveID := getWriterCurveID(w)
		curveName := getTlsCurveIDName(curveID)
		response := fmt.Sprintf("TLS Connection: Curve ID: 0x%x, Name: %v\n", curveID, curveName)

		// Get the cipher suite ID from the writer
		cipherSuite := getWriterCipherSuite(w)
		response += fmt.Sprintf("TLS Connection:	Cipher Suite: 0x%x , Name:%s\n", cipherSuite.ID, cipherSuite.Name)

		w.Write([]byte(response))

	})

	// Create a new TLS configuration
	cfg := &tls.Config{
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
			tls.X25519,			
		},
	}

	srv := &http.Server{
		Addr:         ":443",
		Handler:      mux,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	log.Fatal(srv.ListenAndServeTLS(certFileName, keyFileName))
}
