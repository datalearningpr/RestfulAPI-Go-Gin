package main

import (
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

// function to handle the register new user feature
func register(c *gin.Context) {

	var postData registerUser
	err := c.BindJSON(&postData)
	if err != nil {
		log.Fatal(err)
	}

	userName := postData.UserName
	password := postData.Password

	db, err := sqlx.Connect("sqlite3", "./Blog.db")
	if err != nil {
		log.Fatalln(err)
	}
	defer db.Close()
	selected := []string{}
	db.Select(&selected, "SELECT username FROM User WHERE username = $1;", userName)

	var mapResult map[string]string
	if len(selected) == 0 {
		db.MustExec("INSERT INTO User (username, password) VALUES ($1, $2)", userName, password)
		mapResult = map[string]string{"status": "success", "msg": "succeed!"}

	} else {
		mapResult = map[string]string{"status": "failure", "msg": "username taken!"}
	}
	c.JSON(200, mapResult)
}

// function to handle get the whole post list
func getPostList(c *gin.Context) {

	db, err := sqlx.Connect("sqlite3", "./Blog.db")
	if err != nil {
		log.Fatalln(err)
	}
	defer db.Close()
	blogList := []post{}
	db.Select(&blogList, "SELECT * FROM Post;")

	c.JSON(200, blogList)
}

// function to handle get the comment list of a specific post
func getCommentList(c *gin.Context) {

	db, err := sqlx.Connect("sqlite3", "./Blog.db")
	if err != nil {
		log.Fatalln(err)
	}
	defer db.Close()
	commentList := []comment{}
	postID := c.Param("postId")
	db.Select(&commentList, fmt.Sprintf(`SELECT c.body, u.username, c.timestamp FROM Comment c
		LEFT JOIN User u ON
		c.userid = u.id
		WHERE u.id IS NOT NULL
		AND postid = %s`, postID))

	c.JSON(200, commentList)
}

// function to handle add a new post
func addNewPost(c *gin.Context) {
	var postData newPost
	err := c.BindJSON(&postData)
	if err != nil {
		log.Fatal(err)
	}

	title := postData.Title
	category := postData.Category
	body := postData.Body

	db, err := sqlx.Connect("sqlite3", "./Blog.db")
	if err != nil {
		log.Fatalln(err)
	}
	defer db.Close()

	userID := new(int)
	err = db.Get(&userID, `SELECT id FROM User WHERE username = $1`, c.Request.Header.Get("username"))
	if err != nil {
		log.Fatalln(err)
	}
	db.MustExec("INSERT INTO Post (title, body, category, userid, timestamp) VALUES ($1, $2, $3, $4, $5)",
		title, body, category, userID, time.Now().Format("2006-01-02 15:04:05"))

	mapResult := map[string]string{"status": "success", "msg": "succeed!"}
	c.JSON(200, mapResult)
}

// function to handle add a new comment in a post
func addNewComment(c *gin.Context) {
	var postData newComment
	err := c.BindJSON(&postData)
	if err != nil {
		log.Fatal(err)
	}

	postID := postData.PostID
	comment := postData.Comment

	db, err := sqlx.Connect("sqlite3", "./Blog.db")
	if err != nil {
		log.Fatalln(err)
	}
	defer db.Close()

	userID := new(int)
	err = db.Get(&userID, `SELECT id FROM User WHERE username = $1`, c.Request.Header.Get("username"))
	if err != nil {
		log.Fatalln(err)
	}
	db.MustExec("INSERT INTO Comment (body, userid, postid, timestamp) VALUES ($1, $2, $3, $4)",
		comment, userID, postID, time.Now().Format("2006-01-02 15:04:05"))

	mapResult := map[string]string{"status": "success", "msg": "succeed!"}
	c.JSON(200, mapResult)
}

// function to get the value from claims based on the input key
func getValueFromClaims(key string, claims jwt.Claims) string {
	v := reflect.ValueOf(claims)
	if v.Kind() == reflect.Map {
		for _, k := range v.MapKeys() {
			if fmt.Sprintf("%s", k.Interface()) == key {
				return fmt.Sprintf("%v", v.MapIndex(k).Interface())
			}
		}
	}
	return ""
}

// function to handel the middleware to deal with the JWT token verification
func validateJWT() gin.HandlerFunc {
	return func(c *gin.Context) {

		jwtString := c.Request.Header.Get("Authorization")

		if len(jwtString) > 6 && strings.ToUpper(jwtString[0:7]) == "BEARER " {
			jwtString = jwtString[7:]
		} else if len(jwtString) > 3 && strings.ToUpper(jwtString[0:4]) == "JWT " {
			jwtString = jwtString[4:]
		}

		token, err := jwt.Parse(jwtString,
			func(token *jwt.Token) (interface{}, error) {
				return []byte(secretKey), nil
			})

		if err == nil {
			if token.Valid {
				c.Request.Header.Set("username", getValueFromClaims("username", token.Claims))
				c.Next()
			} else {
				c.String(http.StatusUnauthorized, "Token is not valid")
				c.Abort()
				return
			}
		} else {
			c.String(http.StatusUnauthorized, "Unauthorized access")
			c.Abort()
			return
		}
	}
}

// function to handle login a user
func authenticate(c *gin.Context) {

	var postData registerUser
	err := c.BindJSON(&postData)
	if err != nil {
		log.Fatal(err)
	}

	uesrName := postData.UserName
	password := postData.Password

	db, err := sqlx.Connect("sqlite3", "./Blog.db")
	if err != nil {
		log.Fatalln(err)
	}
	defer db.Close()
	selected := []string{}
	db.Select(&selected, "SELECT username FROM User WHERE username = $1 and password = $2;", uesrName, password)

	var mapResult map[string]string
	var statusCode int
	if len(selected) == 1 {
		loginUser := user{}
		loginUser.UserName = uesrName
		loginUser.ExpiresAt = time.Now().Add(time.Hour * time.Duration(1)).Unix()
		loginUser.IssuedAt = time.Now().Unix()

		token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), &loginUser)
		tokenstring, err := token.SignedString([]byte(secretKey))
		if err != nil {
			log.Fatalln(err)
		}
		statusCode = 200
		mapResult = map[string]string{"access_token": tokenstring}
	} else {
		statusCode = http.StatusUnauthorized
		mapResult = map[string]string{"status": "failure", "msg": "wrong!"}
	}

	c.JSON(statusCode, mapResult)
}

// middleware to handle the cors problem
func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
