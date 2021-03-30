package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gc-backend/internal/model"
	"gc-backend/internal/storage"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	ctxKeyUser ctxKey = iota
	ctxKeyRequestID
	xsollaURL            = "https://store.xsolla.com/api/"
	xsollaVersion        = "v2"
	xsollaAuthentication = "Basic ODUzODA6MTdmZjU5MTk5MGM0NjAwMzcxMmNmMWRiZDA1Nzc2N2Y="
)

var (
	errRecordNotFound        = errors.New("could not find requested record")
	errWhileUpdating         = errors.New("could not update entity")
	errWrongRequestStructure = errors.New("wrong request structure")
	ErrFailedDecodeToken     = errors.New("failed to decode provided token")
	ErrTokenExpired          = errors.New("issued token has expired")
)

type ctxKey int8

type server struct {
	router       *mux.Router
	logger       *logrus.Logger
	storage      storage.Storage
	sessionStore sessions.Store
}

func newServer(storage storage.Storage, sessions sessions.Store) *server {
	s := &server{
		router:       mux.NewRouter(),
		logger:       logrus.New(),
		storage:      storage,
		sessionStore: sessions,
	}

	s.configureRouter()

	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *server) configureRouter() {
	s.router.Use(s.setRequestID)
	s.router.Use(s.logRequest)
	s.router.Use(CORS)

	login := s.router.PathPrefix("/authorised").Subrouter()
	login.Use(s.authorisedUser)

	login.HandleFunc("/project", s.handleProjectCreate()).Methods("POST", "OPTIONS")
	login.HandleFunc("/project", s.handleProjectGET()).Methods("GET", "OPTIONS")
	login.HandleFunc("/project", s.handleProjectDelete()).Methods("DELETE", "OPTIONS")

	login.HandleFunc("/project/{project_id}/card/{sku}", s.handleCardUpdate()).Methods("PUT", "OPTIONS")
	login.HandleFunc("/project/{project_id}/card/{sku}", s.handleGetCard()).Methods("GET", "OPTIONS")
	login.HandleFunc("/project/{project_id}/card", s.handleGetCardsBasic()).Methods("GET", "OPTIONS")

	login.HandleFunc("/project/{project_id}/settings", s.handleSettingsCreate()).Methods("POST", "OPTIONS")
	login.HandleFunc("/project/{project_id}/settings", s.handleGetSettings()).Methods("GET", "OPTIONS")

	login.HandleFunc("/whoami", s.handleWhoami()).Methods("GET", "OPTIONS")
}

func (s *server) handleWhoami() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.respond(w, r, http.StatusOK, "VSE OK")
	}
}

func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set(
			"Access-Control-Allow-Headers",
			"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Token",
		)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
		return
	})
}

func (s *server) setRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.New().String()
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyRequestID, id)))
	})
}

func (s *server) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := s.logger.WithFields(logrus.Fields{
			"Remote_addr": r.RemoteAddr,
			"request_id":  r.Context().Value(ctxKeyRequestID),
		})
		logger.Infof("started %s %s", r.Method, r.RequestURI)

		start := time.Now()
		rw := &responseWriter{w, http.StatusOK}
		next.ServeHTTP(rw, r)

		logger.Infof(
			"completed with %d %s in %v",
			rw.code,
			http.StatusText(rw.code),
			time.Now().Sub(start))
	})
}

func (s *server) error(w http.ResponseWriter, r *http.Request, code int, err error) {
	s.respond(w, r, code, map[string]string{"error": err.Error()})
}

func (s *server) respond(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	w.WriteHeader(code)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

func (s *server) authorisedUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := godotenv.Load(); err != nil {

		}
		signedKey, exist := os.LookupEnv("JWT_KEY")
		if !exist {
			signedKey = os.Getenv("JWT_KEY")
		}
		token, err := verifyToken(r, []byte(signedKey))
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, ErrFailedDecodeToken)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			s.error(w, r, http.StatusInternalServerError, ErrFailedDecodeToken)
			return
		}
		expTime, valid := claims["exp"]
		cur := time.Now().Unix()
		if !valid {
			s.error(w, r, http.StatusInternalServerError, ErrFailedDecodeToken)
			return
		}
		if cur > cast.ToInt64(expTime) {
			s.error(w, r, http.StatusUnauthorized, ErrTokenExpired)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func verifyToken(r *http.Request, signedKey []byte) (*jwt.Token, error) {
	if r.Header["Token"] != nil {
		token, err := jwt.Parse(r.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrFailedDecodeToken
			}
			return signedKey, nil
		})
		if err != nil {
			return nil, err
		}
		return token, nil
	}
	return nil, ErrFailedDecodeToken
}

func (s *server) handleProjectCreate() http.HandlerFunc {
	type request struct {
		ApiKey    string `json:"api_key"`
		ProjectID int    `json:"project_id"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, errWrongRequestStructure)
			return
		}

		p := &model.Project{
			ApiKey:    req.ApiKey,
			ProjectID: req.ProjectID,
		}
		if err := s.storage.Project().Create(p); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}

		s.respond(w, r, http.StatusCreated, p)
	}
}

func (s *server) handleProjectGET() http.HandlerFunc {
	type request struct {
		ApiKey    string `json:"api_key"`
		ProjectID int    `json:"project_id"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, errWrongRequestStructure)
			return
		}

		p := &model.Project{
			ApiKey:    req.ApiKey,
			ProjectID: req.ProjectID,
		}
		pr, err := s.storage.Project().FindByAll(p.ApiKey, p.ProjectID)
		if err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}

		s.respond(w, r, http.StatusCreated, pr)
	}
}

func (s *server) handleProjectDelete() http.HandlerFunc {
	type request struct {
		ApiKey    string `json:"api_key"`
		ProjectID int    `json:"project_id"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, errWrongRequestStructure)
			return
		}

		p := &model.Project{
			ApiKey:    req.ApiKey,
			ProjectID: req.ProjectID,
		}
		err := s.storage.Project().DeleteByAll(p.ApiKey, p.ProjectID)
		if err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}

		s.respond(w, r, http.StatusOK, nil)
	}
}

func (s *server) handleCardUpdate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		projectId := mux.Vars(r)["project_id"]
		sku := mux.Vars(r)["sku"]

		url := xsollaURL + xsollaVersion + fmt.Sprintf("/project/%s/admin/items/game/sku/%s", projectId, sku)

		reqBody, _ := ioutil.ReadAll(r.Body)
		descRu := gjson.GetBytes(reqBody, "description.ru").String()
		descEn := gjson.GetBytes(reqBody, "description.en").String()
		longDescRu := gjson.GetBytes(reqBody, "long_description.ru").String()
		longDescEn := gjson.GetBytes(reqBody, "long_description.en").String()

		res, err := getCard(url)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		resBody, _ := ioutil.ReadAll(res.Body)
		if descRu != "" {
			resBody, _ = sjson.SetBytes(resBody, "description.ru", descRu)
		}
		if descEn != "" {
			resBody, _ = sjson.SetBytes(resBody, "description.en", descEn)
		}
		if longDescRu != "" {
			resBody, _ = sjson.SetBytes(resBody, "long_description.ru", longDescRu)
		}
		if longDescEn != "" {
			resBody, _ = sjson.SetBytes(resBody, "long_description.en", longDescEn)
		}
		newBody := cast.ToString(resBody)
		resData, err := updateCard(url, newBody)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		s.respond(w, r, http.StatusCreated, resData)
	}
}

func (s *server) handleGetCard() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		projectId := mux.Vars(r)["project_id"]
		sku := mux.Vars(r)["sku"]

		url := xsollaURL + xsollaVersion + fmt.Sprintf("/project/%s/admin/items/game/sku/%s", projectId, sku)

		res, err := getCard(url)
		if err != nil {
			s.error(w, r, res.StatusCode, err)
			return
		}
		body, _ := ioutil.ReadAll(res.Body)
		w.Header().Set("Content-Type", "application/json")
		code, er := w.Write(body)
		if er != nil {
			s.error(w, r, code, err)
			return
		}
	}
}

func (s *server) handleGetCardsBasic() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		projectId := mux.Vars(r)["project_id"]
		queryParams := r.URL.RawQuery

		url := xsollaURL + xsollaVersion + fmt.Sprintf("/project/%s/items/game?", projectId) + queryParams

		res, err := getCards(url)
		if err != nil {
			s.error(w, r, res.StatusCode, err)
			return
		}
		body, _ := ioutil.ReadAll(res.Body)
		w.Header().Set("Content-Type", "application/json")
		code, er := w.Write(body)
		if er != nil {
			s.error(w, r, code, err)
			return
		}
	}
}

func (s *server) handleSettingsCreate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		projectId := mux.Vars(r)["project_id"]

		byteString, err := ioutil.ReadAll(r.Body)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, errWrongRequestStructure)
			return
		}
		id := gjson.GetBytes(byteString, "id").String()
		ident := gjson.GetBytes(byteString, "ident").String()
		name := gjson.GetBytes(byteString, "name").String()
		visualOptions := gjson.GetBytes(byteString, "visualOptions").String()

		err = s.storage.Settings().Create(cast.ToInt(projectId), id, ident, name, visualOptions)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		s.respond(w, r, http.StatusCreated, nil)
	}
}

func (s *server) handleGetSettings() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		projectId := mux.Vars(r)["project_id"]

		setting, err := s.storage.Settings().FindByProject(cast.ToInt(projectId))

		if err != nil {
			s.error(w, r, http.StatusNotFound, err)
			return
		}

		er := json.NewEncoder(w).Encode(setting)
		if er != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}
	}
}

func getCard(url string) (*http.Response, error) {
	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("content-type", "application/json")
	req.Header.Add("authorization", xsollaAuthentication)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, errRecordNotFound
	}
	return res, nil
}

func getCards(url string) (*http.Response, error) {
	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("content-type", "application/json")
	req.Header.Add("authorization", xsollaAuthentication)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, errRecordNotFound
	}

	return res, nil
}

func updateCard(url string, bodyString string) (io.ReadCloser, error) {
	payload := strings.NewReader(bodyString)
	req, _ := http.NewRequest("PUT", url, payload)
	req.Header.Add("content-type", "application/json")
	req.Header.Add("authorization", xsollaAuthentication)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 204 {
		return nil, errWhileUpdating
	}
	return res.Body, nil
}
