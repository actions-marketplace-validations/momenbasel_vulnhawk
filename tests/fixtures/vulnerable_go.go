// Intentionally vulnerable Go code for testing VulnHawk.
package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/http"
	"os/exec"
	"path/filepath"
)

var db *sql.DB
var jwtSecret = "hardcoded-secret-key-12345"

// SQL Injection - string concatenation in query
func searchUsers(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	rows, err := db.Query("SELECT * FROM users WHERE name LIKE '%" + query + "%'")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "Results for: %s", query)
}

// IDOR - no authorization check
func getUserProfile(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	var name, email, ssn string
	err := db.QueryRow("SELECT name, email, ssn FROM users WHERE id = ?", userID).Scan(&name, &email, &ssn)
	if err != nil {
		http.Error(w, "Not found", 404)
		return
	}
	// Exposes SSN without auth check
	fmt.Fprintf(w, `{"name":"%s","email":"%s","ssn":"%s"}`, name, email, ssn)
}

// Command Injection
func pingHost(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).Output()
	w.Write(out)
}

// Path Traversal
func serveFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	// No path sanitization
	data, err := ioutil.ReadFile(filepath.Join("/var/uploads", filename))
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	w.Write(data)
}

// Weak Crypto - MD5 for password hashing
func hashPassword(password string) string {
	hash := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", hash)
}

// SSRF - fetches arbitrary URL
func proxyRequest(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	w.Write(body)
}

func main() {
	http.HandleFunc("/search", searchUsers)
	http.HandleFunc("/profile", getUserProfile)
	http.HandleFunc("/ping", pingHost)
	http.HandleFunc("/file", serveFile)
	http.HandleFunc("/proxy", proxyRequest)
	http.ListenAndServe(":8080", nil)
}
