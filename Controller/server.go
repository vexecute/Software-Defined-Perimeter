package main

import (
        "bytes"
        "crypto/tls"
        "crypto/x509"
        "encoding/json"
        "fmt"
        "io/ioutil"
        "log"
        "net/http"
        "os"
        "path/filepath"
)

type User struct {
        Username  string `json:"username"`
        Permission string `json:"permission"`
        Gateway   string `json:"gateway"`
}

var users map[string][]User

// Load permissions from users1.json
func loadPermissions() {
        filePath := "permissions/users.json"
        file, err := os.Open(filePath)
        if err != nil {
                log.Fatalf("Failed to open users.json: %v", err)
        }
        defer file.Close()

        var loadedUsers []User
        decoder := json.NewDecoder(file)
        if err := decoder.Decode(&loadedUsers); err != nil {
                log.Fatalf("Failed to parse users1.json: %v", err)
        }

        users = make(map[string][]User)
        for _, user := range loadedUsers {
                users[user.Username] = append(users[user.Username], user)
        }
}

var servicePorts map[string]int

func loadServicePorts() {
    filePath := "permissions/services.json"
    file, err := os.Open(filePath)
    if err != nil {
        log.Fatalf("Failed to open services.json: %v", err)
    }
    defer file.Close()

    if err := json.NewDecoder(file).Decode(&servicePorts); err != nil {
        log.Fatalf("Failed to parse services.json: %v", err)
    }
}

type Request struct {
        Username string `json:"username"`
        Service  string `json:"service"`
}

type ClientAccess struct {
        ClientIP string            `json:"client_ip"`
        Services map[string]int    `json:"services"` // Services with their associated ports
}

// Send JSON data to the gateway with the server certificate
func sendJSONToGateway(data ClientAccess, gatewayIP string) {
        url := "https://" + gatewayIP + ":8443/receive"
        jsonData, err := json.Marshal(data)
        if err != nil {
                log.Fatalf("Error marshaling JSON: %v", err)
        }

        // Load the server certificate and key for mTLS
        absPathServerCrt, err := filepath.Abs("certs/server.crt")
        if err != nil {
                log.Fatalf("Error getting server certificate path: %v", err)
        }
        absPathServerKey, err := filepath.Abs("certs/server.key")
        if err != nil {
                log.Fatalf("Error getting server key path: %v", err)
        }

        cert, err := tls.LoadX509KeyPair(absPathServerCrt, absPathServerKey)
        if err != nil {
                log.Fatalf("Error loading server certificate: %v", err)
        }

        roots := x509.NewCertPool()
        serverCACert, err := ioutil.ReadFile(absPathServerCrt)
        if err != nil {
                log.Fatalf("Error reading server CA certificate: %v", err)
        }
        roots.AppendCertsFromPEM(serverCACert)

        // Create a transport with TLS configuration
        tlsConf := &tls.Config{
                Certificates: []tls.Certificate{cert}, // Server certificate
                RootCAs:      roots,                   // Server certificate authority
        }

        server := &http.Client{
                Transport: &http.Transport{TLSClientConfig: tlsConf},
        }

        resp, err := server.Post(url, "application/json", bytes.NewBuffer(jsonData))
        if err != nil {
                log.Fatalf("Error sending JSON to Gateway: %v", err)
        }
        defer resp.Body.Close()

        log.Println("JSON sent to Gateway. Response:", resp.Status)
}

// Handle incoming requests from clients
func HelloServer(w http.ResponseWriter, req *http.Request) {
        var requestData Request
        err := json.NewDecoder(req.Body).Decode(&requestData)
        if err != nil {
                http.Error(w, "Invalid request body", http.StatusBadRequest)
                log.Println("Error decoding JSON request body:", err)
                return
        }

        if requestData.Username == "" || requestData.Service == "" {
                http.Error(w, "Username or service cannot be empty", http.StatusBadRequest)
                log.Println("Empty username or service field")
                return
        }

        // Check if the user exists
        userPermissions, exists := users[requestData.Username]
        if !exists {
                http.Error(w, "User not found", http.StatusUnauthorized)
                log.Println("Unauthorized access attempt: User not found -", requestData.Username)
                return
        }

        // Check if the user has permission for the requested service
        var hasPermission bool
        var gateway string
        for _, user := range userPermissions {
                if user.Permission == requestData.Service {
                        hasPermission = true
                        gateway = user.Gateway
                        break
                }
        }

        if !hasPermission {
                http.Error(w, "Unauthorized access: User does not have permission for this service", http.StatusUnauthorized)
                log.Println("Unauthorized service access attempt by user:", requestData.Username, "for service:", requestData.Service)
                return
        }
        // Look up the port for the requested service
    	port, exists := servicePorts[requestData.Service]
    	if !exists {
        	http.Error(w, "Service not found", http.StatusBadRequest)
        	log.Println("Service not found:", requestData.Service)
        	return
    	}
        
        

        // Respond with the permissions and gateway information
        response := map[string]interface{}{
                "message":     "User authorized",
                "permissions": []string{requestData.Service},
                "gateway":     gateway,
        }
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)

        // Build the client access details (Client IP and allowed service)
        clientIP := req.RemoteAddr
        allowedServices := map[string]int{requestData.Service: port}

        clientAccess := ClientAccess{
                ClientIP: clientIP,
                Services: allowedServices,
        }

        // Send client access details to the gateway
        sendJSONToGateway(clientAccess, gateway) // Use the user's respective gateway

        // Respond to the client with a success message
        w.Header().Set("Content-Type", "application/json")
        response1 := map[string]string{
                "message": "Client validated and JSON sent to Gateway.",
        }
        json.NewEncoder(w).Encode(response1)
}

func main() {
        loadPermissions()
        loadServicePorts()

        // Paths for certificates
        absPathServerCrt, err := filepath.Abs("certs/server.crt")
        if err != nil {
                log.Fatalf("Error getting server certificate path: %v", err)
        }
        absPathServerKey, err := filepath.Abs("certs/server.key")
        if err != nil {
                log.Fatalf("Error getting server key path: %v", err)
        }

        // Load client CA certificate to validate incoming client certificates
        absPathClientCACert, err := filepath.Abs("certs/server.crt")
        if err != nil {
                log.Fatalf("Error getting client CA certificate path: %v", err)
        }
        clientCACert, err := ioutil.ReadFile(absPathClientCACert)
        if err != nil {
                log.Fatalf("Error reading client CA certificate: %v", err)
        }

        clientCertPool := x509.NewCertPool()
        clientCertPool.AppendCertsFromPEM(clientCACert)

        // Configure the server's TLS settings
        tlsConfig := &tls.Config{
                ClientAuth:               tls.RequireAndVerifyClientCert,
                ClientCAs:                clientCertPool,
                PreferServerCipherSuites: true,
                MinVersion:               tls.VersionTLS12,
        }

        // Set up HTTP server with TLS
        httpServer := &http.Server{
                Addr:      "192.168.1.4:443",
                TLSConfig: tlsConfig,
        }

        // Set up the HTTP handler
        http.HandleFunc("/", HelloServer)

        // Start the server
        fmt.Println("Running Server on 192.168.1.4:443...")
        err = httpServer.ListenAndServeTLS(absPathServerCrt, absPathServerKey)
        if err != nil {
                log.Fatalf("Server error: %v", err)
        }
}
                 
