package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/NureddinFarzaliyev/go-auth-api/internal/auth"
	"github.com/NureddinFarzaliyev/go-auth-api/internal/httpx"
	"github.com/NureddinFarzaliyev/go-auth-api/internal/middlewares"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type application struct {
	config config
}

type config struct {
	addr string
	db   dbCfg
}

type dbCfg struct {
	mongoConn *mongo.Client
}

func authRoutes(r chi.Router, repo auth.AuthRepository, authMw *middlewares.AuthMiddleware) {
	r.Route("/auth", func(r chi.Router) {
		h := auth.NewAuthHandler(repo)
		r.Post("/register", h.Register)
		r.Post("/login", h.Login)
		r.Group(func(r chi.Router) {
			r.Use(authMw.Middleware)
			r.Get("/logout", h.Logout)
		})
	})
}

func protectedRoutes(r chi.Router, authMw *middlewares.AuthMiddleware) {
	r.Group(func(r chi.Router) {
		r.Use(authMw.Middleware)
		r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
			email := r.Context().Value(auth.UserEmailContext).(string)
			msg := fmt.Sprintf("Welcome, %s!", email)
			httpx.JSON(w, http.StatusOK, httpx.Envelope{"message": msg})
		})
	})

}

func (app *application) mount() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Logger)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Route("/v1", func(r chi.Router) {
		memoAuthRepo := auth.NewMemoryAuthRepository()
		authMw := middlewares.NewAuthMiddleware(memoAuthRepo)

		authRoutes(r, memoAuthRepo, authMw)
		protectedRoutes(r, authMw)
	})

	r.Route("/v2", func(r chi.Router) {
		mongoAuthRepo := auth.NewMongoAuthRepository(app.config.db.mongoConn)
		authMw := middlewares.NewAuthMiddleware(mongoAuthRepo)

		authRoutes(r, mongoAuthRepo, authMw)
		protectedRoutes(r, authMw)
	})

	return r
}

func (app *application) run(mux http.Handler) error {
	srv := http.Server{
		Addr:         app.config.addr,
		Handler:      mux,
		WriteTimeout: time.Second * 30,
		ReadTimeout:  time.Second * 10,
		IdleTimeout:  time.Minute,
	}

	fmt.Printf("App started on port %s\n", app.config.addr)
	return srv.ListenAndServe()
}
