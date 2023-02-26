package utils

import (
	"go-clean-architecture-rest/internal/models"
	"math/rand"
	"strings"
)

const alphabet = "abcdefghijklmnopqrstuvwxyz"

// RandomString generates a random string of length n
func RandomString(n int) string {
	var sb strings.Builder
	k := len(alphabet)

	for i := 0; i < n; i++ {
		c := alphabet[rand.Intn(k)]
		sb.WriteByte(c)
	}

	return sb.String()
}

func RandomUser() models.User {
	gender := "male"
	role := "user"
	return models.User{
		FirstName: RandomString(10),
		LastName:  RandomString(10),
		Email:     "email@gmail.com",
		Password:  RandomString(10),
		Gender:    &gender,
		Role:      &role,
	}
}
