package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─── Config ──────────────────────────────────────────────────────────────────

type Config struct {
	Port         string
	SharedSecret string
	DataFile     string
	LogLevel     string
}

func loadConfig() Config {
	cfg := Config{
		Port:         getEnv("PORT", "8080"),
		SharedSecret: mustEnv("SHARED_SECRET"),
		DataFile:     getEnv("DATA_FILE", "cf_ip_data.json"),
		LogLevel:     getEnv("LOG_LEVEL", "info"),
	}
	return cfg
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Fprintf(os.Stderr, "fatal: environment variable %q is required\n", key)
		os.Exit(1)
	}
	return v
}

// ─── Domain types ─────────────────────────────────────────────────────────────

var validISPs = []string{"移动", "联通", "电信", "多线", "IPV6"}

type IncomingRecord struct {
	ISP       string `json:"isp"`
	IP        string `json:"ip"`
	Loss      string `json:"loss"`
	Ping      string `json:"ping"`
	Speed     string `json:"speed"`
	Bandwidth string `json:"bandwidth"`
	Timestamp string `json:"timestamp"`
}

type ReportRequest struct {
	Timestamp string           `json:"timestamp"`
	Records   []IncomingRecord `json:"records"`
}

type IPRecord struct {
	IP         string  `json:"ip"`
	PacketLoss string  `json:"packet_loss"`
	Latency    float64 `json:"latency"`
	Speed      string  `json:"speed"`
	Bandwidth  string  `json:"bandwidth"`
	Timestamp  string  `json:"timestamp"`
}

type Payload struct {
	ReceivedAt      string                `json:"received_at"`
	SourceTimestamp string                `json:"source_timestamp"`
	Data            map[string][]IPRecord `json:"data"`
}

// ─── Store ────────────────────────────────────────────────────────────────────

type Store struct {
	mu       sync.RWMutex
	dataFile string
}

func NewStore(dataFile string) *Store {
	return &Store{dataFile: dataFile}
}

func (s *Store) Write(p *Payload) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	tmp := s.dataFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	return os.Rename(tmp, s.dataFile)
}

func (s *Store) Read() (*Payload, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	b, err := os.ReadFile(s.dataFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	var p Payload
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &p, nil
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

type Server struct {
	cfg    Config
	store  *Store
	logger *slog.Logger
}

func NewServer(cfg Config, store *Store, logger *slog.Logger) *Server {
	return &Server{cfg: cfg, store: store, logger: logger}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/cf-ip-report", s.handleReport)
	mux.HandleFunc("GET /api/cf-ip-data", s.handleData)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return s.withMiddleware(mux)
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CFIP-Secret")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration", time.Since(start).String(),
		)
	})
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-CFIP-Secret") != s.cfg.SharedSecret {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid secret"})
		return
	}

	var req ReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if len(req.Records) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty records"})
		return
	}

	ispData := make(map[string][]IPRecord, len(validISPs))
	for _, isp := range validISPs {
		ispData[isp] = []IPRecord{}
	}

	for _, r := range req.Records {
		if _, ok := ispData[r.ISP]; !ok {
			continue
		}
		latency, err := parseLatency(r.Ping)
		if err != nil {
			continue
		}
		ispData[r.ISP] = append(ispData[r.ISP], IPRecord{
			IP:         r.IP,
			PacketLoss: r.Loss,
			Latency:    latency,
			Speed:      r.Speed,
			Bandwidth:  r.Bandwidth,
			Timestamp:  r.Timestamp,
		})
	}

	for isp := range ispData {
		sort.Slice(ispData[isp], func(i, j int) bool {
			return ispData[isp][i].Latency < ispData[isp][j].Latency
		})
	}

	payload := &Payload{
		ReceivedAt:      time.Now().UTC().Format(time.RFC3339),
		SourceTimestamp: req.Timestamp,
		Data:            ispData,
	}

	if err := s.store.Write(payload); err != nil {
		s.logger.Error("store write failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage error"})
		return
	}

	counts := make(map[string]int, len(validISPs))
	for _, isp := range validISPs {
		counts[isp] = len(ispData[isp])
	}
	s.logger.Info("report received",
		"移动", counts["移动"], "联通", counts["联通"],
		"电信", counts["电信"], "多线", counts["多线"], "IPV6", counts["IPV6"],
	)

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "counts": counts})
}

func (s *Server) handleData(w http.ResponseWriter, r *http.Request) {
	payload, err := s.store.Read()
	if err != nil {
		s.logger.Error("store read failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage error"})
		return
	}
	if payload == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no data yet"})
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func parseLatency(s string) (float64, error) {
	s = strings.TrimSuffix(strings.TrimSpace(s), "ms")
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid latency %q", s)
	}
	return v, nil
}

// ─── Entry point ──────────────────────────────────────────────────────────────

func main() {
	cfg := loadConfig()

	level := slog.LevelInfo
	if strings.ToLower(cfg.LogLevel) == "debug" {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	// Ensure data directory exists
	if dir := filepath.Dir(cfg.DataFile); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			logger.Error("failed to create data directory", "err", err)
			os.Exit(1)
		}
	}

	store := NewStore(cfg.DataFile)
	srv := NewServer(cfg, store, logger)

	httpSrv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      srv.routes(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	logger.Info("server starting", "port", cfg.Port, "data_file", cfg.DataFile)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}
