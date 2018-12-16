package main

import (
	"log"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
)

// secret key used in JWT token
const secretKey string = "just a simple jwt"

func main() {
	// use GIN as framework
	router := gin.Default()
	router.Use(cors())
	router.POST("/api/blog/login", authenticate)
	router.GET("/api/blog/postlist", getPostList)
	router.GET("/api/blog/post/:postId/commentlist", getCommentList)
	router.POST("/api/blog/register", register)
	router.POST("/api/blog/post", validateJWT(), addNewPost)
	router.POST("/api/blog/comment", validateJWT(), addNewComment)

	err := router.Run(":5000")
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
