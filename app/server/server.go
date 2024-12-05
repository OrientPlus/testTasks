package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"StudyProject/app/entity"
	"StudyProject/app/repository"
	"StudyProject/app/tokens"
	"github.com/sirupsen/logrus"
)

type Server struct {
	server   *http.Server
	repo     *repository.Repo
	tokensUC *tokens.UcHandler
	context  context.Context
	logger   logrus.Logger
}

func NewServer() (*Server, error) {

	s := Server{
		tokensUC: tokens.NewUcHandler(os.Getenv("SECRET")),
	}

	file, err := os.OpenFile("logs.txt", os.O_CREATE|os.O_RDWR|os.O_APPEND, 0777)
	if err != nil {
		return nil, err
	}

	s.logger = logrus.Logger{
		Out:          file,
		Formatter:    nil,
		ReportCaller: false,
		Level:        logrus.InfoLevel,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", s.Login)
	mux.HandleFunc("/refresh", s.Refresh)

	port := os.Getenv("WEB_SERVER_PORT")

	s.server = &http.Server{
		Addr:    "localhost:" + port,
		Handler: mux,
	}

	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASS")
	dbName := os.Getenv("DB_NAME")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbSSLMode := os.Getenv("DB_SSLMODE")
	dbCreds := "user=" + dbUser + " password=" + dbPass + " dbname=" + dbName + " host=" + dbHost + " port=" + dbPort + " sslmode=" + dbSSLMode

	s.repo, err = repository.NewRepo(dbCreds)
	if err != nil {
		return nil, entity.ErrCannotInitDatabase
	}

	return &s, nil
}

func (s *Server) Run() error {
	err := s.server.ListenAndServe()

	return err
}

func (s *Server) Close() error {
	err := s.server.Close()

	return err
}

func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	ip := strings.Split(r.RemoteAddr, ":")[0]
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		s.logger.Errorf("Handling an invalid request type from an IP: %s", ip)
		return
	}

	var req entity.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		s.logger.Errorf("Invalid JSON from IP: %s", ip)
		return
	}

	if req.Login == "" || req.GUID == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		s.logger.Errorf("Missing required fields; IP: %s", ip)
		return
	}

	sessionID := s.GenerateSessionID()
	tokens, err := s.tokensUC.GenerateTokens(entity.TokensParams{
		UserLogin: req.Login,
		UserGUID:  req.GUID,
		UserIP:    ip,
		SessionID: sessionID,
	})
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		s.logger.Errorf("Failed to generate access token: %s; IP: %s", err.Error(), ip)
		return
	}

	s.repo.RemoveToken(nil, repository.TokenDTO{
		Token: tokens.RefreshToken,
	})

	err = s.repo.AddToken(nil, repository.TokenDTO{
		Token:     tokens.RefreshToken,
		SessionID: sessionID,
		IpAddress: ip,
		CreatedAt: time.Now(),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := entity.Tokens{
		AccessToken:  tokens.AccessToken,
		RefreshToken: base64.StdEncoding.EncodeToString(tokens.RefreshToken),
	}
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		s.logger.Errorf("Failed to encode access tokens: %s", err.Error())
	}
}

func (s *Server) Refresh(w http.ResponseWriter, r *http.Request) {
	ip := strings.Split(r.RemoteAddr, ":")[0]
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		s.logger.Errorf("Handling an invalid request type from an IP: %s", ip)
		return
	}

	var req entity.Tokens
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		s.logger.Errorf("Invalid JSON from IP: %s", ip)
		return
	}

	if req.RefreshToken == "" || req.AccessToken == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		s.logger.Errorf("Missing required fields; IP: %s", ip)
		return
	}

	rawRefreshToken, err := base64.StdEncoding.DecodeString(req.RefreshToken)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		s.logger.Errorf("Invalid refresh token from IP: %s", ip)
		return
	}
	rawTokens := entity.RawTokens{
		AccessToken:  req.AccessToken,
		RefreshToken: rawRefreshToken,
	}

	ok, err := s.tokensUC.CheckRefreshToken(rawTokens)
	if !ok {
		http.Error(w, "Invalid refresh token", http.StatusBadRequest)
		s.logger.Errorf("Invalid token received from IP: %s", ip)
		return
	}

	// TODO
	//  Проверить токен в бд
	//  Проверить время жизни
	//  Сгенерировать новую пару
	//  Обновить токены в бд
}

func (s *Server) GenerateSessionID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
