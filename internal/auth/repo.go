package auth

type AuthRepository interface {
	Register(User) error
}
