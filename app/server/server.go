package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"StudyProject/app/entity"
	"StudyProject/app/mailer"
	"StudyProject/app/repository"
	"StudyProject/app/tokens"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type Server struct {
	server   *http.Server
	repo     *repository.Repo
	tokensUC *tokens.TokensUC
	mailerUC *mailer.MailerUC
	logger   *logrus.Logger
}

func NewServer() (*Server, error) {

	secret := os.Getenv("SECRET")
	if secret == "" {
		return nil, entity.ErrEnvArgumentEmpty
	}
	s := Server{
		tokensUC: tokens.NewUcHandler(secret),
		mailerUC: mailer.NewMailer(os.Getenv("MAILER_USER"), os.Getenv("MAILER_PASS")),
	}

	file, err := os.OpenFile("logs.txt", os.O_CREATE|os.O_RDWR|os.O_APPEND, 0777)
	if err != nil {
		return nil, err
	}

	s.logger = logrus.New()
	s.logger.SetOutput(io.MultiWriter(file, os.Stdout))
	s.logger.SetLevel(logrus.DebugLevel)
	s.logger.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/login", s.Login)
	mux.HandleFunc("/refresh", s.Refresh)
	mux.HandleFunc("/some_route", s.LoginAccessRoute)

	port := os.Getenv("WEB_SERVER_PORT")

	s.server = &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	dbUser := os.Getenv("POSTGRES_USER")
	dbPass := os.Getenv("POSTGRES_PASS")
	dbName := os.Getenv("POSTGRES_NAME")
	dbHost := os.Getenv("POSTGRES_HOST")
	dbPort := os.Getenv("POSTGRES_PORT")
	dbSSLMode := os.Getenv("POSTGRES_SSL_MODE")
	dbCreds := "user=" + dbUser + " password=" + dbPass + " dbname=" + dbName + " host=" + dbHost + " port=" + dbPort + " sslmode=" + dbSSLMode

	fmt.Printf("DB config: %s\n", dbCreds)
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
	// Выделяем ip адрес и проверяем метод
	ip := strings.Split(r.RemoteAddr, ":")[0]
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		s.logger.Errorf("Handling an invalid request type from an IP: %s", ip)
		return
	}

	// Десериализуем полученный json
	var req entity.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		s.logger.Errorf("Invalid JSON from IP: %s", ip)
		return
	}

	// По хорошему тут должен быть валидатор данных)
	if req.Login == "" || req.GUID == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		s.logger.Errorf("Missing required fields; IP: %s", ip)
		return
	}

	// Удаляем токен от этого пользователя если он уже был в базе
	err := s.repo.RemoveToken(context.Background(), s.GenerateSessionID(req.Login))
	if err != nil {
		s.logger.Errorf("Error removing token: %s", err)
	}

	// Генерируем новую пару
	tokens, err := s.createTokenPair(entity.TokensParams{
		UserLogin: req.Login,
		UserGUID:  req.GUID,
		UserIP:    ip,
	})
	if err != nil {
		http.Error(w, "Failed to generate token pair", http.StatusInternalServerError)
		s.logger.Errorf("Failed to generate token pair: %s; IP: %s", err.Error(), ip)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(tokens)
	if err != nil {
		s.logger.Errorf("Failed to encode access tokens: %s", err.Error())
	}
}

func (s *Server) Refresh(w http.ResponseWriter, r *http.Request) {
	// Выделяем ip адрес и проверяем метод запроса
	ip := strings.Split(r.RemoteAddr, ":")[0]
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		s.logger.Errorf("Handling an invalid request type from an IP: %s", ip)
		return
	}

	// Сериализуем json в структуру
	var req entity.Tokens
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		s.logger.Errorf("Invalid JSON from IP: %s", ip)
		return
	}

	// Проверяем что не пустые
	// По хорошему тут нужен валидатор данных
	if req.RefreshToken == "" || req.AccessToken == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		s.logger.Errorf("Missing required fields; IP: %s", ip)
		return
	}

	// Декодируем из base64 в исходный хеш токена
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

	// Проверяем пару токенов. Валидность access токена и восстанавливаем refresh токен
	claims, ok, err := s.tokensUC.CheckTokenPair(rawTokens)
	if !ok || err != nil {
		http.Error(w, "Invalid refresh token", http.StatusBadRequest)
		s.logger.Errorf("Invalid token received from IP: %s", ip)
		return
	}

	// Достаем из БД сохраненный ранее токен
	srcRefreshToken, err := s.repo.GetRefreshToken(context.Background(), claims.SessionID)
	if err != nil {
		http.Error(w, "Token verification error", http.StatusForbidden)
		s.logger.Errorf("No token found for the specified SessionID: %s; IP: %s", err.Error(), ip)
		return
	}

	// Сравниваем полученный токен с токеном из БД
	if !bytes.Equal(srcRefreshToken.Token, rawRefreshToken) {
		http.Error(w, "Invalid refresh token", http.StatusBadRequest)
		s.logger.Errorf("Invalid refresh token from IP: %s", ip)
		return
	}

	// Проверяем время жизни токена
	if time.Now().After(srcRefreshToken.ExpTime) {
		http.Error(w, "The refresh token has expired", http.StatusForbidden)
		s.logger.Errorf("The token's lifetime has expired; Attempt to use with IP: %s", ip)
		return
	}

	// Если ip сменился, отправляем предупреждение на почту
	if claims.UserIP == ip {
		err = s.mailerUC.SendWarning(claims.UserLogin)
		if err != nil {
			s.logger.Warnf("it was not possible to send a warning about the ip address change to the mail %s; error: %s", claims.UserLogin, err.Error())
		}
	}

	// Удаляем старый токен из бд
	err = s.repo.RemoveToken(context.Background(), claims.SessionID)
	if err != nil {
		s.logger.Warnf("Failed to remove token: %s; IP: %s", err.Error(), ip)
	}

	// Генерируем новую пару токенов
	tokens, err := s.createTokenPair(entity.TokensParams{
		UserLogin: claims.UserLogin,
		UserGUID:  claims.UserGUID,
		UserIP:    ip,
	})
	if err != nil {
		http.Error(w, "Failed to generate token pair", http.StatusInternalServerError)
		s.logger.Errorf("Failed to generate token pair: %s; IP: %s", err.Error(), ip)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(tokens)
	if err != nil {
		s.logger.Errorf("Failed to encode access tokens: %s", err.Error())
	}
}

func (s *Server) LoginAccessRoute(w http.ResponseWriter, r *http.Request) {
	ok, err := s.tokensUC.CheckAccessToken(r.Header.Get("Authorization"))
	if !ok || err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "Hello, authorized user!")
}

// Генерирует UUID5 на основе login пользователя (почта), что гарантирует уникальность генерируемого идентификатора сессии
func (s *Server) GenerateSessionID(email string) string {
	return uuid.NewSHA1(uuid.NameSpaceDNS, []byte(email)).String()
}

func (s *Server) createTokenPair(params entity.TokensParams) (entity.Tokens, error) {
	params.SessionID = s.GenerateSessionID(params.UserLogin)
	s.logger.Debugf("Generated session ID: %s", params.SessionID)
	tokens, err := s.tokensUC.GenerateTokens(params)
	if err != nil {
		s.logger.Errorf("Failed to generate access token: %s; IP: %s", err.Error(), params.UserIP)
		return entity.Tokens{}, errors.New("Failed to generate access token")
	}

	err = s.repo.AddToken(context.Background(), repository.TokenDTO{
		Token:     tokens.RefreshToken,
		SessionID: params.SessionID,
		IpAddress: params.UserIP,
		ExpTime:   time.Now().Add(10 * time.Minute),
	})

	return entity.Tokens{
		AccessToken:  tokens.AccessToken,
		RefreshToken: base64.StdEncoding.EncodeToString(tokens.RefreshToken),
	}, err
}
