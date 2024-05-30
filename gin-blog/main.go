package main

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var jwtKey = []byte("my_secret_key")

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func main() {
	router := gin.Default()

	// Serve static files
	router.LoadHTMLFiles("templates/index.html")

	router.POST("/login", login)
	router.GET("/", showPosts)
	router.POST("/create", authenticate, createPost)
	router.POST("/update/:id", authenticate, updatePost)
	router.POST("/delete/:id", authenticate, deletePost)

	router.Run("localhost:8081")
}

type Post struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

var posts = []Post{
	{ID: "1", Title: "First Post", Content: "This is my first post"},
	{ID: "2", Title: "Second Post", Content: "This is my second post"},
}

func showPosts(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"posts": posts,
	})
}

func createPost(c *gin.Context) {
	id := c.PostForm("id")
	title := c.PostForm("title")
	content := c.PostForm("content")

	newPost := Post{
		ID:      id,
		Title:   title,
		Content: content,
	}
	posts = append(posts, newPost)

	c.Redirect(http.StatusFound, "/")
}

func updatePost(c *gin.Context) {
	id := c.Param("id")
	title := c.PostForm("title")
	content := c.PostForm("content")

	for i, p := range posts {
		if p.ID == id {
			posts[i].Title = title
			posts[i].Content = content
			break
		}
	}

	c.Redirect(http.StatusFound, "/")
}

func deletePost(c *gin.Context) {
	id := c.Param("id")

	for i, p := range posts {
		if p.ID == id {
			posts = append(posts[:i], posts[i+1:]...)
			break
		}
	}

	c.Redirect(http.StatusFound, "/")
}

func login(c *gin.Context) {
	var creds Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if creds.Username != "user" || creds.Password != "password" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create token"})
		return
	}

	c.SetCookie("token", tokenString, 300, "/", "localhost", false, true)
	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func authenticate(c *gin.Context) {
	tokenString, err := c.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token"})
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token signature"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token"})
		return
	}
	if !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	c.Next()
}
