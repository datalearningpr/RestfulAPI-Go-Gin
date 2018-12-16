package main

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type post struct {
	ID        int       `db:"id" json:"id"`
	Title     string    `db:"title" json:"title"`
	Body      string    `db:"body" json:"body"`
	Category  string    `db:"category" json:"category"`
	UserID    string    `db:"userid" json:"userid"`
	Timestamp time.Time `db:"timestamp" json:"timestamp"`
}

type newPost struct {
	Title    string `db:"title" json:"title"`
	Body     string `db:"body" json:"body"`
	Category string `db:"category" json:"category"`
}

type comment struct {
	Body      string    `db:"body" json:"body"`
	UserName  string    `db:"username" json:"username"`
	Timestamp time.Time `db:"timestamp" json:"timestamp"`
}

type newComment struct {
	PostID  int    `json:"postId"`
	Comment string `json:"comment"`
}

type registerUser struct {
	UserName string `db:"username" json:"username"`
	Password string `db:"password" json:"password"`
}

type user struct {
	UserName string `json:"username"`
	jwt.StandardClaims
}
