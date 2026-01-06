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
)

type application struct {
	config config
}

type config struct {
	addr string
}

func (app *application) mount() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Logger)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Route("/v1", func(r chi.Router) {
		authMemoRepo := auth.NewAuthMemoryTaskRepository()
		authMw := middlewares.NewAuthMiddleware(authMemoRepo)
		r.Route("/auth", func(r chi.Router) {
			h := auth.NewAuthHandler(authMemoRepo)
			r.Post("/register", h.Register)
			r.Post("/login", h.Login)
			r.Group(func(r chi.Router) {
				r.Use(authMw.Middleware)
				r.Get("/logout", h.Logout)
			})
		})
		r.Group(func(r chi.Router) {
			r.Use(authMw.Middleware)
			r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
				email := r.Context().Value(auth.UserEmailContext).(string)
				msg := fmt.Sprintf("Welcome, %s!", email)
				httpx.JSON(w, http.StatusOK, httpx.Envelope{"message": msg})
			})
		})
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
