package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/NureddinFarzaliyev/go-auth-api/internal/httpx"
	"github.com/NureddinFarzaliyev/go-auth-api/internal/utils"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"golang.org/x/crypto/bcrypt"
)

type MongoAuthRepository struct {
	conn  *mongo.Client
	users *mongo.Collection
}

var _ AuthRepository = &MongoAuthRepository{}

func NewMongoAuthRepository(conn *mongo.Client) *MongoAuthRepository {
	users := conn.Database("test").Collection("users")
	return &MongoAuthRepository{
		conn:  conn,
		users: users,
	}
}

func (r *MongoAuthRepository) IsValidSession(ctx context.Context, loginToken string, csrfToken string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	filter := bson.D{{Key: "meta.session_token", Value: loginToken}, {Key: "meta.csrf_token", Value: csrfToken}}
	existingUser := r.users.FindOne(ctx, filter)

	if existingUser.Err() != nil {
		return "", httpx.ErrorNotAuthorized
	}

	var user User
	existingUser.Decode(&user)

	now := time.Now()
	expires_at := user.Meta.ExpiresAt
	isExpired := now.After(expires_at)

	if isExpired {
		return "", httpx.ErrorNotAuthorized
	}

	email := user.Email
	return email, nil
}

func (r *MongoAuthRepository) Register(ctx context.Context, user User) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	filter := bson.D{{Key: "email", Value: user.Email}}
	fmt.Println("Registering user with email:", user.Email)

	existingUser := r.users.FindOne(ctx, filter)
	fmt.Println("Existing user check error:", existingUser.Err())

	if existingUser.Err() == nil {
		return httpx.ErrorAlreadyRegistered
	}
	fmt.Println("No existing user found, proceeding with registration.")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	fmt.Println("Hashed password:", string(hashedPassword))
	if err != nil {
		return httpx.ErrorInternal
	}

	newUser := User{
		Email:    user.Email,
		Password: string(hashedPassword),
	}
	fmt.Println("Inserting new user:", newUser.Email)

	_, err = r.users.InsertOne(ctx, newUser)
	if err != nil {
		fmt.Println("Error inserting new user:", err)
		return httpx.ErrorInternal
	}

	fmt.Println("User registered successfully:", newUser.Email)
	return nil
}

func (r *MongoAuthRepository) Login(ctx context.Context, user UserLogin) (token string, csrf string, expires time.Time, err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	filter := bson.D{{Key: "email", Value: user.Email}}
	userExists := r.users.FindOne(ctx, filter)
	if userExists.Err() != nil {
		return "", "", time.Time{}, httpx.ErrorUserNotFoundOrWrongCredentials
	}

	var existingUser User
	userExists.Decode(&existingUser)

	correctPass := bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(user.Password))
	if correctPass != nil {
		return "", "", time.Time{}, httpx.ErrorUserNotFoundOrWrongCredentials
	}

	loginToken, err := utils.GenerateToken()
	if err != nil {
		return "", "", time.Time{}, httpx.ErrorInternal
	}

	loginExpires := time.Now().Add(24 * time.Hour)

	csrfToken, err := utils.GenerateToken()
	if err != nil {
		return "", "", time.Time{}, httpx.ErrorInternal
	}

	update := bson.M{
		"$set": bson.M{
			"meta.session_token": loginToken,
			"meta.expires_at":    loginExpires,
			"meta.csrf_token":    csrfToken,
		},
	}

	_, err = r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		return "", "", time.Time{}, httpx.ErrorInternal
	}

	return loginToken, csrfToken, loginExpires, nil
}

func (r *MongoAuthRepository) Logout(ctx context.Context, email string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	filter := bson.D{{Key: "email", Value: email}}
	userExists := r.users.FindOne(ctx, filter)
	if userExists.Err() != nil {
		return httpx.ErrorInternal
	}

	update := bson.M{
		"$set": bson.M{
			"meta.csrf_token":    "",
			"meta.session_token": "",
			"meta.expires_at":    time.Now(),
		},
	}

	_, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		return httpx.ErrorInternal
	}
	return nil
}
