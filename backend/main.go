package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var db *sql.DB

// ---------------- MODELS ----------------

type User struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}

type Asset struct {
	ID        int    `json:"id"`
	Hostname  string `json:"hostname"`
	IP        string `json:"ip"`
	Type      string `json:"type"`
	CreatedAt string `json:"created_at"`
}

type Vulnerability struct {
	ID          int     `json:"id"`
	CVEID       string  `json:"cve_id"`
	Title       string  `json:"title"`
	AssetID     int     `json:"asset_id"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	Description string  `json:"description"`
	Status      string  `json:"status"`
	CreatedAt   string  `json:"created_at"`
}

type SecurityLog struct {
	ID          int    `json:"id"`
	UserID      int    `json:"user_id"`
	Username    string `json:"username"`
	EventType   string `json:"event_type"`
	Description string `json:"description"`
	IPAddress   string `json:"ip_address"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
}

type Incident struct {
	ID             int    `json:"id"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	Status         string `json:"status"`
	ReportedBy     int    `json:"reported_by"`
	ReportedByName string `json:"reported_by_name"`
	AssignedTo     string `json:"assigned_to"`
	Resolution     string `json:"resolution"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

// ---------------- SESSION MANAGEMENT ----------------

type Session struct {
	UserID    int
	ExpiresAt time.Time
}

var (
	sessions   = make(map[string]Session)
	sessionMux sync.Mutex
)

const sessionDuration = 24 * time.Hour

// ---------------- DATABASE ----------------

func initDB() error {
	if err := os.MkdirAll("../database", 0755); err != nil {
		return err
	}

	var err error

	db, err = sql.Open("sqlite", "../database/database.db")
	if err != nil {
		return err
	}

	db.SetMaxOpenConns(1)

	if err = db.Ping(); err != nil {
		return err
	}

	if _, err = db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		return err
	}

	// Create database tables
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'analyst',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS assets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hostname TEXT NOT NULL,
		ip TEXT NOT NULL,
		type TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		cve_id TEXT,
		title TEXT NOT NULL,
		asset_id INTEGER NOT NULL,
		severity TEXT NOT NULL,
		cvss REAL NOT NULL,
		description TEXT,
		status TEXT NOT NULL DEFAULT 'Open',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(asset_id) REFERENCES assets(id)
	);

	CREATE TABLE IF NOT EXISTS security_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		username TEXT,
		event_type TEXT NOT NULL,
		description TEXT,
		ip_address TEXT,
		status TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS incidents (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		description TEXT,
		category TEXT NOT NULL,
		severity TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'Open',
		reported_by INTEGER NOT NULL,
		assigned_to TEXT DEFAULT '',
		resolution TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(reported_by) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS threat_intelligence (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip_address TEXT NOT NULL,
		domain_name TEXT NOT NULL DEFAULT '',
		classification TEXT NOT NULL,
		risk TEXT NOT NULL,
		details TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS scan_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		target TEXT NOT NULL,
		start_port INTEGER NOT NULL,
		end_port INTEGER NOT NULL,
		total_scanned INTEGER NOT NULL,
		total_found INTEGER NOT NULL,
		results_json TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`

	if _, err := db.Exec(schema); err != nil {
		return err
	}

	// Check whether domain_name column exists
	rows, err := db.Query(`PRAGMA table_info(threat_intelligence)`)
	if err != nil {
		return err
	}

	domainColumnExists := false

	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString

		if err := rows.Scan(
			&cid,
			&name,
			&columnType,
			&notNull,
			&defaultValue,
			&primaryKey,
		); err != nil {
			rows.Close()
			return err
		}

		if name == "domain_name" {
			domainColumnExists = true
		}
	}

	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}

	rows.Close()

	// Add domain_name for existing databases
	if !domainColumnExists {
		if _, err := db.Exec(`
			ALTER TABLE threat_intelligence
			ADD COLUMN domain_name TEXT NOT NULL DEFAULT ''
		`); err != nil {
			return err
		}

		log.Println("Added domain_name column successfully")
	}

	log.Println("Database initialized successfully")

	return nil
}

// ---------------- COMMON HELPERS ----------------

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return err
	}

	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request must contain only one JSON object")
	}

	return nil
}

func validEmail(email string) bool {
	return regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`).MatchString(email)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func allowedMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		jsonResponse(w, http.StatusMethodNotAllowed,
			map[string]string{"error": "Method not allowed"})
		return false
	}
	return true
}

// ---------------- SECURITY LOGGING ----------------

func logSecurityEvent(userID int, username, eventType, description, ip, status string) {
	if db == nil {
		return
	}

	var userValue interface{}
	if userID > 0 {
		userValue = userID
	}

	_, err := db.Exec(`
		INSERT INTO security_logs
		(user_id, username, event_type, description, ip_address, status)
		VALUES (?, ?, ?, ?, ?, ?)`,
		userValue, username, eventType, description, ip, status)

	if err != nil {
		log.Println("Security log error:", err)
	}
}

// ---------------- AUTHENTICATION ----------------

func createSession(userID int) (string, error) {
	tokenBytes := make([]byte, 32)

	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}

	token := hex.EncodeToString(tokenBytes)

	sessionMux.Lock()
	sessions[token] = Session{
		UserID:    userID,
		ExpiresAt: time.Now().Add(sessionDuration),
	}
	sessionMux.Unlock()

	return token, nil
}

func getAuthenticatedUser(r *http.Request) (User, bool) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return User{}, false
	}

	sessionMux.Lock()
	session, exists := sessions[cookie.Value]

	if exists && time.Now().After(session.ExpiresAt) {
		delete(sessions, cookie.Value)
		exists = false
	}
	sessionMux.Unlock()

	if !exists {
		return User{}, false
	}

	var user User

	err = db.QueryRow(`
		SELECT id, name, email, role, created_at
		FROM users WHERE id = ?`,
		session.UserID,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Role,
		&user.CreatedAt,
	)

	if err != nil {
		return User{}, false
	}

	return user, true
}

func requireAuth(w http.ResponseWriter, r *http.Request) (User, bool) {
	user, ok := getAuthenticatedUser(r)

	if !ok {
		jsonResponse(w, http.StatusUnauthorized,
			map[string]string{"error": "Authentication required"})
		return User{}, false
	}

	return user, true
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if !allowedMethod(w, r, http.MethodPost) {
		return
	}

	var input struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := decodeJSON(w, r, &input); err != nil {
		jsonResponse(w, http.StatusBadRequest,
			map[string]string{"error": "Invalid JSON"})
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))

	if input.Name == "" || !validEmail(input.Email) ||
		len(input.Password) < 8 || len(input.Password) > 72 {
		jsonResponse(w, http.StatusBadRequest,
			map[string]string{"error": "Enter a name, valid email and password of 8-72 bytes"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(input.Password), bcrypt.DefaultCost,
	)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError,
			map[string]string{"error": "Password processing failed"})
		return
	}

	result, err := db.Exec(`
		INSERT INTO users (name, email, password_hash, role)
		VALUES (?, ?, ?, 'analyst')`,
		input.Name, input.Email, string(hash),
	)

	if err != nil {
		jsonResponse(w, http.StatusConflict,
			map[string]string{"error": "Email may already be registered"})
		return
	}

	id, _ := result.LastInsertId()

	logSecurityEvent(int(id), input.Name, "REGISTER",
		"New account registered", clientIP(r), "Success")

	jsonResponse(w, http.StatusCreated,
		map[string]string{"message": "Registration successful"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if !allowedMethod(w, r, http.MethodPost) {
		return
	}

	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := decodeJSON(w, r, &input); err != nil {
		jsonResponse(w, http.StatusBadRequest,
			map[string]string{"error": "Invalid JSON"})
		return
	}

	input.Email = strings.ToLower(strings.TrimSpace(input.Email))

	var user User
	var passwordHash string

	err := db.QueryRow(`
		SELECT id, name, email, password_hash, role, created_at
		FROM users WHERE email = ?`,
		input.Email,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&passwordHash,
		&user.Role,
		&user.CreatedAt,
	)

	if err != nil || bcrypt.CompareHashAndPassword(
		[]byte(passwordHash), []byte(input.Password),
	) != nil {
		logSecurityEvent(0, input.Email, "LOGIN",
			"Failed login attempt", clientIP(r), "Failed")

		jsonResponse(w, http.StatusUnauthorized,
			map[string]string{"error": "Invalid email or password"})
		return
	}

	token, err := createSession(user.ID)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError,
			map[string]string{"error": "Could not create session"})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Local development only; use true with HTTPS.
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(sessionDuration),
	})

	logSecurityEvent(user.ID, user.Name, "LOGIN",
		"User logged in", clientIP(r), "Success")

	jsonResponse(w, http.StatusOK,
		map[string]interface{}{
			"message": "Login successful",
			"user":    user,
		})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if !allowedMethod(w, r, http.MethodPost) {
		return
	}

	user, authenticated := getAuthenticatedUser(r)

	if cookie, err := r.Cookie("session"); err == nil {
		sessionMux.Lock()
		delete(sessions, cookie.Value)
		sessionMux.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	if authenticated {
		logSecurityEvent(user.ID, user.Name, "LOGOUT",
			"User logged out", clientIP(r), "Success")
	}

	jsonResponse(w, http.StatusOK,
		map[string]string{"message": "Logged out successfully"})
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	if !allowedMethod(w, r, http.MethodGet) {
		return
	}

	user, ok := requireAuth(w, r)
	if !ok {
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"user": user,
	})
}

// ---------------- ASSETS ----------------

func assetsHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := requireAuth(w, r)
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodGet:
		rows, err := db.Query(`
			SELECT id, hostname, ip, type, created_at
			FROM assets ORDER BY id DESC`)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError,
				map[string]string{"error": "Could not load assets"})
			return
		}
		defer rows.Close()

		assets := make([]Asset, 0)

		for rows.Next() {
			var a Asset
			if err := rows.Scan(
				&a.ID, &a.Hostname, &a.IP, &a.Type, &a.CreatedAt,
			); err != nil {
				jsonResponse(w, http.StatusInternalServerError,
					map[string]string{"error": "Could not read assets"})
				return
			}
			assets = append(assets, a)
		}

		jsonResponse(w, http.StatusOK,
			map[string]interface{}{"total": len(assets), "assets": assets})

	case http.MethodPost:
		var input struct {
			Hostname string `json:"hostname"`
			IP       string `json:"ip"`
			Type     string `json:"type"`
		}

		if err := decodeJSON(w, r, &input); err != nil {
			jsonResponse(w, http.StatusBadRequest,
				map[string]string{"error": "Invalid JSON"})
			return
		}

		input.Hostname = strings.TrimSpace(input.Hostname)
		input.IP = strings.TrimSpace(input.IP)

		validTypes := map[string]bool{
			"Server":          true,
			"Workstation":     true,
			"Network Device":  true,
			"Virtual Machine": true,
		}

		if input.Hostname == "" || net.ParseIP(input.IP) == nil ||
			!validTypes[input.Type] {
			jsonResponse(w, http.StatusBadRequest,
				map[string]string{"error": "Invalid hostname, IP or asset type"})
			return
		}

		result, err := db.Exec(`
			INSERT INTO assets (hostname, ip, type)
			VALUES (?, ?, ?)`,
			input.Hostname, input.IP, input.Type,
		)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError,
				map[string]string{"error": "Could not create asset"})
			return
		}

		id, _ := result.LastInsertId()

		logSecurityEvent(user.ID, user.Name, "ASSET_CREATED",
			"Created asset "+input.Hostname, clientIP(r), "Success")

		jsonResponse(w, http.StatusCreated,
			map[string]interface{}{"message": "Asset created", "id": id})

	case http.MethodDelete:
		id, err := strconv.Atoi(r.URL.Query().Get("id"))
		if err != nil || id < 1 {
			jsonResponse(w, http.StatusBadRequest,
				map[string]string{"error": "Valid asset id required"})
			return
		}

		result, err := db.Exec(`DELETE FROM assets WHERE id = ?`, id)
		if err != nil {
			jsonResponse(w, http.StatusConflict,
				map[string]string{"error": "Asset may be linked to vulnerabilities"})
			return
		}

		count, _ := result.RowsAffected()
		if count == 0 {
			jsonResponse(w, http.StatusNotFound,
				map[string]string{"error": "Asset not found"})
			return
		}

		logSecurityEvent(user.ID, user.Name, "ASSET_DELETED",
			"Deleted asset", clientIP(r), "Success")

		jsonResponse(w, http.StatusOK,
			map[string]string{"message": "Asset deleted"})

	default:
		jsonResponse(w, http.StatusMethodNotAllowed,
			map[string]string{"error": "Method not allowed"})
	}
}

// ---------------- VULNERABILITIES ----------------

func vulnerabilitiesHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := requireAuth(w, r)
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodGet:
		rows, err := db.Query(`
			SELECT id, cve_id, title, asset_id, severity,
			       cvss, description, status, created_at
			FROM vulnerabilities ORDER BY id DESC`)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError,
				map[string]string{"error": "Could not load vulnerabilities"})
			return
		}
		defer rows.Close()

		items := make([]Vulnerability, 0)

		for rows.Next() {
			var v Vulnerability
			var cve, description sql.NullString

			if err := rows.Scan(
				&v.ID, &cve, &v.Title, &v.AssetID, &v.Severity,
				&v.CVSS, &description, &v.Status, &v.CreatedAt,
			); err != nil {
				jsonResponse(w, http.StatusInternalServerError,
					map[string]string{"error": "Could not read vulnerabilities"})
				return
			}

			v.CVEID = cve.String
			v.Description = description.String
			items = append(items, v)
		}

		jsonResponse(w, http.StatusOK,
			map[string]interface{}{"total": len(items), "vulnerabilities": items})

	case http.MethodPost:
		var input struct {
			CVEID       string  `json:"cve_id"`
			Title       string  `json:"title"`
			AssetID     int     `json:"asset_id"`
			Severity    string  `json:"severity"`
			CVSS        float64 `json:"cvss"`
			Description string  `json:"description"`
		}

		if err := decodeJSON(w, r, &input); err != nil {
			jsonResponse(w, http.StatusBadRequest,
				map[string]string{"error": "Invalid JSON"})
			return
		}

		input.CVEID = strings.TrimSpace(input.CVEID)
		input.Title = strings.TrimSpace(input.Title)

		validSeverity := map[string]bool{
			"Critical": true, "High": true, "Medium": true, "Low": true,
		}

		if input.Title == "" || input.AssetID < 1 ||
			!validSeverity[input.Severity] ||
			input.CVSS < 0 || input.CVSS > 10 {
			jsonResponse(w, http.StatusBadRequest,
				map[string]string{"error": "Invalid vulnerability information"})
			return
		}

		if input.CVEID != "" &&
			!regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`).MatchString(input.CVEID) {
			jsonResponse(w, http.StatusBadRequest,
				map[string]string{"error": "Invalid CVE ID format"})
			return
		}

		result, err := db.Exec(`
			INSERT INTO vulnerabilities
			(cve_id, title, asset_id, severity, cvss, description, status)
			VALUES (?, ?, ?, ?, ?, ?, 'Open')`,
			input.CVEID, input.Title, input.AssetID,
			input.Severity, input.CVSS, input.Description,
		)

		if err != nil {
			jsonResponse(w, http.StatusBadRequest,
				map[string]string{"error": "Could not create vulnerability; check asset ID"})
			return
		}

		id, _ := result.LastInsertId()

		logSecurityEvent(user.ID, user.Name, "VULNERABILITY_CREATED",
			"Created vulnerability "+input.Title, clientIP(r), "Success")

		jsonResponse(w, http.StatusCreated,
			map[string]interface{}{"message": "Vulnerability created", "id": id})

	case http.MethodDelete:
		id, err := strconv.Atoi(r.URL.Query().Get("id"))
		if err != nil || id < 1 {
			jsonResponse(w, http.StatusBadRequest,
				map[string]string{"error": "Valid vulnerability id required"})
			return
		}

		result, err := db.Exec(`DELETE FROM vulnerabilities WHERE id = ?`, id)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError,
				map[string]string{"error": "Could not delete vulnerability"})
			return
		}

		count, _ := result.RowsAffected()
		if count == 0 {
			jsonResponse(w, http.StatusNotFound,
				map[string]string{"error": "Vulnerability not found"})
			return
		}

		logSecurityEvent(user.ID, user.Name, "VULNERABILITY_DELETED",
			"Deleted vulnerability", clientIP(r), "Success")

		jsonResponse(w, http.StatusOK,
			map[string]string{"message": "Vulnerability deleted"})

	default:
		jsonResponse(w, http.StatusMethodNotAllowed,
			map[string]string{"error": "Method not allowed"})
	}
}

func vulnerabilityStatusHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := requireAuth(w, r)
	if !ok {
		return
	}

	if !allowedMethod(w, r, http.MethodPatch) {
		return
	}

	idText := strings.TrimPrefix(r.URL.Path, "/api/vulnerabilities/")
	idText = strings.TrimSuffix(idText, "/status")

	id, err := strconv.Atoi(idText)
	if err != nil || id < 1 {
		jsonResponse(w, http.StatusBadRequest,
			map[string]string{"error": "Invalid vulnerability id"})
		return
	}

	var input struct {
		Status string `json:"status"`
	}

	if err := decodeJSON(w, r, &input); err != nil {
		jsonResponse(w, http.StatusBadRequest,
			map[string]string{"error": "Invalid JSON"})
		return
	}

	valid := map[string]bool{
		"Open": true, "In Progress": true, "Resolved": true,
	}

	if !valid[input.Status] {
		jsonResponse(w, http.StatusBadRequest,
			map[string]string{"error": "Invalid status"})
		return
	}

	result, err := db.Exec(`
		UPDATE vulnerabilities SET status = ? WHERE id = ?`,
		input.Status, id,
	)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError,
			map[string]string{"error": "Could not update status"})
		return
	}

	count, _ := result.RowsAffected()
	if count == 0 {
		jsonResponse(w, http.StatusNotFound,
			map[string]string{"error": "Vulnerability not found"})
		return
	}

	logSecurityEvent(user.ID, user.Name, "VULNERABILITY_UPDATED",
		"Updated vulnerability status", clientIP(r), "Success")

	jsonResponse(w, http.StatusOK,
		map[string]string{"message": "Vulnerability status updated"})
}

// ---------------- SECURITY LOGS ----------------

func securityLogHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAuth(w, r); !ok {
		return
	}

	if !allowedMethod(w, r, http.MethodGet) {
		return
	}

	rows, err := db.Query(`
		SELECT id, COALESCE(user_id, 0), COALESCE(username, ''),
		       event_type, COALESCE(description, ''),
		       COALESCE(ip_address, ''), COALESCE(status, ''),
		       created_at
		FROM security_logs
		ORDER BY id DESC LIMIT 200`)

	if err != nil {
		jsonResponse(w, http.StatusInternalServerError,
			map[string]string{"error": "Could not load security logs"})
		return
	}
	defer rows.Close()

	logs := make([]SecurityLog, 0)

	for rows.Next() {
		var item SecurityLog

		if err := rows.Scan(
			&item.ID, &item.UserID, &item.Username,
			&item.EventType, &item.Description,
			&item.IPAddress, &item.Status, &item.CreatedAt,
		); err != nil {
			jsonResponse(w, http.StatusInternalServerError,
				map[string]string{"error": "Could not read security logs"})
			return
		}

		logs = append(logs, item)
	}

	jsonResponse(w, http.StatusOK,
		map[string]interface{}{"total": len(logs), "logs": logs})
}

// ---------------- INCIDENTS ----------------

func incidentsHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := requireAuth(w, r)
	if !ok {
		return
	}

	switch r.Method {

	case http.MethodGet:
		rows, err := db.Query(`
			SELECT i.id, i.title, COALESCE(i.description, ''),
			       i.category, i.severity, i.status, i.reported_by,
			       COALESCE(u.name, ''), COALESCE(i.assigned_to, ''),
			       COALESCE(i.resolution, ''), i.created_at, i.updated_at
			FROM incidents i
			LEFT JOIN users u ON i.reported_by = u.id
			ORDER BY i.id DESC`)

		if err != nil {
			jsonResponse(w, http.StatusInternalServerError,
				map[string]string{"error": "Could not load incidents"})
			return
		}
		defer rows.Close()

		items := make([]Incident, 0)

		for rows.Next() {
			var item Incident

			if err := rows.Scan(
				&item.ID, &item.Title, &item.Description,
				&item.Category, &item.Severity, &item.Status,
				&item.ReportedBy, &item.ReportedByName,
				&item.AssignedTo, &item.Resolution,
				&item.CreatedAt, &item.UpdatedAt,
			); err != nil {
				jsonResponse(w, http.StatusInternalServerError,
					map[string]string{"error": "Could not read incidents"})
				return
			}

			items = append(items, item)
		}

		jsonResponse(w, http.StatusOK,
			map[string]interface{}{"total": len(items), "incidents": items})

	case http.MethodPost:
		var input struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Category    string `json:"category"`
			Severity    string `json:"severity"`
		}

		if err := decodeJSON(w, r, &input); err != nil {
			jsonResponse(w, http.StatusBadRequest,
				map[string]string{"error": "Invalid JSON"})
			return
		}

		input.Title = strings.TrimSpace(input.Title)
		input.Category = strings.TrimSpace(input.Category)

		validSeverity := map[string]bool{
			"Low": true, "Medium": true, "High": true, "Critical": true,
		}

		if input.Title == "" || input.Category == "" ||
			!validSeverity[input.Severity] {
			jsonResponse(w, http.StatusBadRequest,
				map[string]string{"error": "Enter title, category and valid severity"})
			return
		}

		result, err := db.Exec(`
			INSERT INTO incidents
			(title, description, category, severity, reported_by)
			VALUES (?, ?, ?, ?, ?)`,
			input.Title, input.Description, input.Category,
			input.Severity, user.ID,
		)

		if err != nil {
			jsonResponse(w, http.StatusInternalServerError,
				map[string]string{"error": "Could not create incident"})
			return
		}

		id, _ := result.LastInsertId()

		logSecurityEvent(user.ID, user.Name, "INCIDENT_CREATED",
			"Created incident "+input.Title, clientIP(r), "Success")

		jsonResponse(w, http.StatusCreated,
			map[string]interface{}{
				"message":     "Incident created",
				"incident_id": id,
			})

	default:
		jsonResponse(w, http.StatusMethodNotAllowed,
			map[string]string{"error": "Method not allowed"})
	}
}

func incidentUpdateHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := requireAuth(w, r)
	if !ok {
		return
	}

	// Get incident ID from URL
	idText := strings.TrimPrefix(r.URL.Path, "/api/incidents/")
	idText = strings.TrimSuffix(idText, "/")

	id, err := strconv.Atoi(idText)
	if err != nil || id < 1 {
		jsonResponse(w, http.StatusBadRequest,
			map[string]string{"error": "Invalid incident id"})
		return
	}

	switch r.Method {

	case http.MethodDelete:
		result, err := db.Exec(
			`DELETE FROM incidents WHERE id = ?`, id,
		)

		if err != nil {
			log.Println("Incident deletion error:", err)
			jsonResponse(w, http.StatusInternalServerError,
				map[string]string{"error": "Could not delete incident"})
			return
		}

		count, err := result.RowsAffected()
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError,
				map[string]string{"error": "Could not verify deletion"})
			return
		}

		if count == 0 {
			jsonResponse(w, http.StatusNotFound,
				map[string]string{"error": "Incident not found"})
			return
		}

		logSecurityEvent(user.ID, user.Name, "INCIDENT_DELETED",
			"Deleted incident ID "+strconv.Itoa(id),
			clientIP(r), "Success")

		jsonResponse(w, http.StatusOK,
			map[string]string{"message": "Incident deleted successfully"})

	case http.MethodPatch:
		var input struct {
			Status     string `json:"status"`
			AssignedTo string `json:"assigned_to"`
			Resolution string `json:"resolution"`
		}

		if err := decodeJSON(w, r, &input); err != nil {
			jsonResponse(w, http.StatusBadRequest,
				map[string]string{"error": "Invalid JSON"})
			return
		}

		if input.Status == "" && input.AssignedTo == "" && input.Resolution == "" {
			jsonResponse(w, http.StatusBadRequest,
				map[string]string{"error": "At least one update field is required"})
			return
		}

		if input.Status != "" {
			valid := map[string]bool{
				"Open": true, "In Progress": true,
				"Resolved": true, "Closed": true,
			}

			if !valid[input.Status] {
				jsonResponse(w, http.StatusBadRequest,
					map[string]string{"error": "Invalid incident status"})
				return
			}
		}

		result, err := db.Exec(`
			UPDATE incidents
			SET status = CASE WHEN ? = '' THEN status ELSE ? END,
			    assigned_to = CASE WHEN ? = '' THEN assigned_to ELSE ? END,
			    resolution = CASE WHEN ? = '' THEN resolution ELSE ? END,
			    updated_at = CURRENT_TIMESTAMP
			WHERE id = ?`,
			input.Status, input.Status,
			input.AssignedTo, input.AssignedTo,
			input.Resolution, input.Resolution,
			id,
		)

		if err != nil {
			jsonResponse(w, http.StatusInternalServerError,
				map[string]string{"error": "Could not update incident"})
			return
		}

		count, _ := result.RowsAffected()
		if count == 0 {
			jsonResponse(w, http.StatusNotFound,
				map[string]string{"error": "Incident not found"})
			return
		}

		logSecurityEvent(user.ID, user.Name, "INCIDENT_UPDATED",
			"Updated incident ID "+strconv.Itoa(id),
			clientIP(r), "Success")

		jsonResponse(w, http.StatusOK,
			map[string]string{"message": "Incident updated successfully"})

	default:
		jsonResponse(w, http.StatusMethodNotAllowed,
			map[string]string{"error": "Method not allowed"})
	}
}

// ---------------- HEALTH CHECK ----------------

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if !allowedMethod(w, r, http.MethodGet) {
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{
		"message": "Cyber Portal backend is running",
		"status":  "online",
	})
}

func dashboardStatsHandler(w http.ResponseWriter, r *http.Request) {
	if !allowedMethod(w, r, http.MethodGet) {
		return
	}

	if _, ok := requireAuth(w, r); !ok {
		return
	}

	var assets, vulnerabilities, incidents, logs int

	err := db.QueryRow(`
        SELECT
            (SELECT COUNT(*) FROM assets),
            (SELECT COUNT(*) FROM vulnerabilities),
            (SELECT COUNT(*) FROM incidents WHERE status = 'Open'),
            (SELECT COUNT(*) FROM security_logs)
    `).Scan(&assets, &vulnerabilities, &incidents, &logs)

	if err != nil {
		jsonResponse(w, http.StatusInternalServerError,
			map[string]string{"error": "Could not load dashboard statistics"})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]int{
		"total_assets":          assets,
		"total_vulnerabilities": vulnerabilities,
		"open_incidents":        incidents,
		"total_security_logs":   logs,
	})
}

// ---------------- CORS ----------------

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if origin == "http://localhost:5500" ||
			origin == "http://127.0.0.1:5500" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Add("Vary", "Origin")
		}

		w.Header().Set("Access-Control-Allow-Methods",
			"GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers",
			"Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func threatIntelligenceHandler(w http.ResponseWriter, r *http.Request) {
	if !allowedMethod(w, r, http.MethodPost) {
		return
	}

	if _, ok := requireAuth(w, r); !ok {
		return
	}

	var request struct {
		IPAddress string `json:"ip_address"`
	}

	if err := decodeJSON(w, r, &request); err != nil {
		jsonResponse(w, http.StatusBadRequest,
			map[string]string{"error": "Invalid request"})
		return
	}

	ip := net.ParseIP(strings.TrimSpace(request.IPAddress))

	if ip == nil || ip.To4() == nil {
		jsonResponse(w, http.StatusBadRequest,
			map[string]string{"error": "Invalid IPv4 address"})
		return
	}

	ipAddress := ip.To4().String()
	domainName := reverseDNSLookup(ipAddress)

	classification := "Unverified"
	risk := "Unknown"
	details := "IP format validated. Reverse DNS lookup completed. No external threat intelligence provider is connected yet."

	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		classification = "Internal"
		risk = "Informational"
		details = "Private, loopback, or link-local IP address. This is not an external threat reputation result."
	}

	_, err := db.Exec(`
		INSERT INTO threat_intelligence
		(ip_address, domain_name, classification, risk, details)
		VALUES (?, ?, ?, ?, ?)
	`, ipAddress, domainName, classification, risk, details)

	if err != nil {
		log.Println("Threat intelligence database error:", err)

		jsonResponse(w, http.StatusInternalServerError,
			map[string]string{"error": "Could not save investigation"})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{
		"ip_address":     ipAddress,
		"domain_name":    domainName,
		"classification": classification,
		"risk":           risk,
		"details":        details,
	})
}

func dataManagementHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed,
			map[string]string{"error": "Method not allowed"})
		return
	}

	if _, ok := requireAuth(w, r); !ok {
		return
	}

	action := strings.TrimPrefix(r.URL.Path, "/api/settings/")

	tables := map[string][]string{
		"clear-scan-history": {
			"scan_history",
		},
		"clear-security-logs": {
			"security_logs",
		},
		"reset-all-data": {
			"scan_history",
			"security_logs",
			"threat_intelligence",
			"incidents",
			"vulnerabilities",
			"assets",
		},
	}

	selectedTables, exists := tables[action]
	if !exists {
		jsonResponse(w, http.StatusBadRequest,
			map[string]string{"error": "Invalid data management action"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError,
			map[string]string{"error": "Could not start database transaction"})
		return
	}
	defer tx.Rollback()

	for _, table := range selectedTables {
		query := "DELETE FROM " + table

		if _, err := tx.Exec(query); err != nil {
			log.Printf("Data reset failed on table %s: %v", table, err)

			jsonResponse(w, http.StatusInternalServerError,
				map[string]string{
					"error": "Failed to clear " + table,
				})
			return
		}
	}

	if err := tx.Commit(); err != nil {
		jsonResponse(w, http.StatusInternalServerError,
			map[string]string{"error": "Failed to complete data operation"})
		return
	}

	jsonResponse(w, http.StatusOK,
		map[string]string{"message": "Data cleared successfully"})
}

func reverseDNSLookup(ip string) string {
	names, err := net.LookupAddr(ip)

	if err != nil || len(names) == 0 {
		return "No hostname found"
	}

	return strings.TrimSuffix(names[0], ".")
}

// ---------------- MAIN ----------------

func main() {
	if err := initDB(); err != nil {
		log.Fatal("Database initialization failed:", err)
	}
	defer db.Close()

	mux := http.NewServeMux()

	mux.HandleFunc("/api/health", healthHandler)
	mux.HandleFunc("/api/dashboard/stats", dashboardStatsHandler)

	mux.HandleFunc("/api/register", registerHandler)
	mux.HandleFunc("/api/login", loginHandler)
	mux.HandleFunc("/api/logout", logoutHandler)
	mux.HandleFunc("/api/me", meHandler)

	mux.HandleFunc("/api/assets", assetsHandler)

	mux.HandleFunc("/api/vulnerabilities", vulnerabilitiesHandler)
	mux.HandleFunc("/api/vulnerabilities/", vulnerabilityStatusHandler)

	mux.HandleFunc("/api/security-logs", securityLogHandler)
	mux.HandleFunc("/api/threat-intelligence/lookup", threatIntelligenceHandler)
	mux.HandleFunc("/api/incidents", incidentsHandler)
	mux.HandleFunc("/api/incidents/", incidentUpdateHandler)
	mux.HandleFunc("/api/settings/", dataManagementHandler)

	// scanHandler is defined in scanner.go
	mux.HandleFunc("/api/scan", scanHandler)

	handler := corsMiddleware(mux)

	server := &http.Server{
		Addr:              ":8080",
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Println("Cyber Portal backend running at http://localhost:8080")
	log.Fatal(server.ListenAndServe())
}
