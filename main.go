package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/ini.v1"
)

// --- Models ---

type PlayerInfo struct {
	Name        string  `json:"name"`
	AccountName string  `json:"accountName"`
	PlayerId    string  `json:"playerId"`
	UserId      string  `json:"userId"`
	IP          string  `json:"ip"`
	Ping        float64 `json:"ping"`
	LocationX   float64 `json:"location_x"`
	LocationY   float64 `json:"location_y"`
	Level       int     `json:"level"`
}

type PalGetPlayerResponse struct {
	Players []PlayerInfo `json:"players"`
}

type PalServerUserActionParams struct {
	UserId  string `json:"userid"`
	Message string `json:"message"`
}

type Config struct {
	ServerHost           string
	ServerPort           int
	ServerUser           string
	ServerPass           string
	CheckInterval        time.Duration
	EnforcerPort         int
	WhitelistFile        string
	PendingFile          string
	NonWhitelistAction   string
	MinAutoWhitelistUser int
	KickMessage          string
	BanMessage           string
}

// --- Global State ---

var (
	config        Config
	startTime     time.Time
	whitelist     map[string]bool
	whitelistLock sync.RWMutex
	pending       []string
	pendingLock   sync.Mutex
)

// --- Logic ---

func loadConfig() {
	cfg, err := ini.Load("config.ini")
	if err != nil {
		log.Printf("Warning: Fail to read config.ini: %v. Using defaults.", err)
		cfg = ini.Empty()
	}

	config.ServerHost = cfg.Section("server").Key("host").MustString("127.0.0.1")
	config.ServerPort = cfg.Section("server").Key("port").MustInt(8212)
	config.ServerUser = cfg.Section("server").Key("username").String()
	config.ServerPass = cfg.Section("server").Key("password").String()
	config.CheckInterval = cfg.Section("server").Key("check_interval").MustDuration(5 * time.Second)

	config.EnforcerPort = cfg.Section("enforcer").Key("port").MustInt(8080)
	config.WhitelistFile = cfg.Section("enforcer").Key("whitelist_file").MustString("whitelist.txt")
	config.PendingFile = cfg.Section("enforcer").Key("pending_file").MustString("pending.txt")
	config.NonWhitelistAction = cfg.Section("enforcer").Key("non_whitelist_action").MustString("pending")
	config.MinAutoWhitelistUser = cfg.Section("enforcer").Key("min_autowhitelist_user").MustInt(0)
	config.KickMessage = cfg.Section("enforcer").Key("kick_message").MustString("you are not whitelisted")
	config.BanMessage = cfg.Section("enforcer").Key("ban_message").MustString("request access to your friend or owner")
}

func loadWhitelist() {
	whitelistLock.Lock()
	defer whitelistLock.Unlock()
	whitelist = make(map[string]bool)
	data, err := os.ReadFile(config.WhitelistFile)
	if err != nil {
		if os.IsNotExist(err) {
			os.WriteFile(config.WhitelistFile, []byte(""), 0644)
			return
		}
		log.Printf("Error reading whitelist: %v", err)
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		id := strings.TrimSpace(line)
		if id != "" {
			whitelist[id] = true
		}
	}
}

func saveWhitelist() {
	whitelistLock.RLock()
	defer whitelistLock.RUnlock()
	var sb strings.Builder
	for id := range whitelist {
		sb.WriteString(id + "\n")
	}
	os.WriteFile(config.WhitelistFile, []byte(sb.String()), 0644)
}

func loadPending() {
	pendingLock.Lock()
	defer pendingLock.Unlock()
	data, err := os.ReadFile(config.PendingFile)
	if err != nil {
		if os.IsNotExist(err) {
			os.WriteFile(config.PendingFile, []byte(""), 0644)
			return
		}
		log.Printf("Error reading pending: %v", err)
		return
	}
	lines := strings.Split(string(data), "\n")
	pending = []string{}
	for _, line := range lines {
		id := strings.TrimSpace(line)
		if id != "" {
			pending = append(pending, id)
		}
	}
}

func addToPending(userId string) {
	pendingLock.Lock()
	defer pendingLock.Unlock()
	// Check if already in pending
	for _, id := range pending {
		if id == userId {
			return
		}
	}
	pending = append(pending, userId)
	savePendingLocked()
}

func savePendingLocked() {
	var sb strings.Builder
	for _, id := range pending {
		sb.WriteString(id + "\n")
	}
	err := os.WriteFile(config.PendingFile, []byte(sb.String()), 0644)
	if err != nil {
		log.Printf("Error saving pending file: %v", err)
	}
}

func getAuthHeader() string {
	auth := config.ServerUser + ":" + config.ServerPass
	if auth == ":" {
		return "Basic YWRtaW46YWRtaW4="
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

func palRequest(method, path string, body interface{}) ([]byte, error) {
	url := fmt.Sprintf("http://%s:%d/v1/api%s", config.ServerHost, config.ServerPort, path)
	var bodyReader io.Reader
	if body != nil {
		jsonBody, _ := json.Marshal(body)
		bodyReader = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", getAuthHeader())
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return data, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(data))
	}

	return data, nil
}

func checkPlayers() {
	// Periodic check
	data, err := palRequest("GET", "/players", nil)
	if err != nil {
		log.Printf("Error getting players: %v", err)
		return
	}

	var resp PalGetPlayerResponse
	err = json.Unmarshal(data, &resp)
	if err != nil {
		log.Printf("Error unmarshalling players: %v", err)
		return
	}

	whitelistLock.Lock()
	changed := false

	for _, player := range resp.Players {
		if !whitelist[player.UserId] {
			if len(whitelist) < config.MinAutoWhitelistUser {
				log.Printf("Whitelisting player %s (%s) automatically (min_autowhitelist_user=%d)", player.Name, player.UserId, config.MinAutoWhitelistUser)
				whitelist[player.UserId] = true
				changed = true
				continue
			}

			action := strings.ToLower(config.NonWhitelistAction)

			switch action {
			case "kick":
				log.Printf("Player %s (%s) not in whitelist. Kicking...", player.Name, player.UserId)
				_, err := palRequest("POST", "/kick", PalServerUserActionParams{UserId: player.UserId, Message: config.KickMessage})
				if err != nil {
					log.Printf("Failed to kick player %s: %v", player.UserId, err)
				}
				addToPending(player.UserId)

			case "ban":
				log.Printf("Player %s (%s) not in whitelist. Banning...", player.Name, player.UserId)
				_, err := palRequest("POST", "/ban", PalServerUserActionParams{UserId: player.UserId, Message: config.BanMessage})
				if err != nil {
					log.Printf("Failed to ban player %s: %v", player.UserId, err)
				}
				// No pending for "ban" action as per user request

			case "pending":
				log.Printf("Player %s (%s) not in whitelist. Banning and adding to pending...", player.Name, player.UserId)
				_, err := palRequest("POST", "/ban", PalServerUserActionParams{UserId: player.UserId, Message: config.BanMessage})
				if err != nil {
					log.Printf("Failed to ban player %s: %v", player.UserId, err)
				}
				addToPending(player.UserId)

			default:
				// Default to "pending" behavior if unknown
				log.Printf("Unknown action %s, defaulting to pending for player %s", action, player.UserId)
				palRequest("POST", "/ban", PalServerUserActionParams{UserId: player.UserId, Message: config.BanMessage})
				addToPending(player.UserId)
			}
		}
	}
	whitelistLock.Unlock()

	if changed {
		saveWhitelist()
	}
}

// --- Handlers ---

func infoHandler(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(startTime)
	fmt.Fprintf(w, "Alive. Uptime: %s", uptime.String())
}

func pendingHandler(w http.ResponseWriter, r *http.Request) {
	pendingLock.Lock()
	defer pendingLock.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pending)
}

func whitelistHandler(w http.ResponseWriter, r *http.Request) {
	whitelistLock.RLock()
	defer whitelistLock.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	var list []string
	for id := range whitelist {
		list = append(list, id)
	}
	json.NewEncoder(w).Encode(list)
}

func permitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var params struct {
		UserId string `json:"userid"`
	}
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil || params.UserId == "" {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}

	whitelistLock.Lock()
	whitelist[params.UserId] = true
	whitelistLock.Unlock()
	saveWhitelist()

	// Try to unban the user in case they were banned
	log.Printf("Unbanning user %s...", params.UserId)
	_, err = palRequest("POST", "/unban", PalServerUserActionParams{UserId: params.UserId})
	if err != nil {
		log.Printf("Failed to unban user %s: %v (they might not have been banned)", params.UserId, err)
	}

	// Remove from pending
	pendingLock.Lock()
	for i, id := range pending {
		if id == params.UserId {
			pending = append(pending[:i], pending[i+1:]...)
			savePendingLocked()
			break
		}
	}
	pendingLock.Unlock()

	fmt.Fprintf(w, "User %s permitted", params.UserId)
}

func main() {
	startTime = time.Now()
	loadConfig()
	loadWhitelist()
	loadPending()

	// Initial auth check / info check as requested
	log.Printf("Testing connection to PalServer...")
	_, err := palRequest("GET", "/info", nil)
	if err != nil {
		log.Printf("Warning: Initial connection to PalServer failed: %v", err)
	} else {
		log.Printf("Connected to PalServer successfully.")
	}

	// Start checker
	go func() {
		ticker := time.NewTicker(config.CheckInterval)
		for range ticker.C {
			checkPlayers()
		}
	}()

	// Start HTTP server
	http.HandleFunc("/v1/api/info", infoHandler)
	http.HandleFunc("/v1/api/pending/", pendingHandler)
	http.HandleFunc("/v1/api/whitelist/", whitelistHandler)
	http.HandleFunc("/v1/api/permit/", permitHandler)

	addr := fmt.Sprintf(":%d", config.EnforcerPort)
	log.Printf("Enforcer API listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
