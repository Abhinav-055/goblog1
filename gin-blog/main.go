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

type Post struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

var posts = []Post{
	{ID: "1", Title: "First Post", Content: "This is my first post"},
	{ID: "2", Title: "Second Post", Content: "This is my second post"},
}

var users = make(map[string]string)

func main() {
	router := gin.Default()

	router.POST("/register", register)
	router.POST("/login", login)
	router.POST("/create", authenticate, createPost)
	router.PUT("/update/:id", authenticate, updatePost)    // Change to PUT
	router.DELETE("/delete/:id", authenticate, deletePost) // Change to DELETE

	router.Run("localhost:8081")
}
func register(c *gin.Context) {
	var creds Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Check if username already exists
	if _, exists := users[creds.Username]; exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	// Store username and password in memory
	users[creds.Username] = creds.Password

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}

func login(c *gin.Context) {
	var creds Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Check if user exists and password matches
	if storedPassword, exists := users[creds.Username]; !exists || storedPassword != creds.Password {
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

	c.JSON(http.StatusOK, gin.H{"message": "Post created successfully"})
}

func updatePost(c *gin.Context) {
	id := c.Param("id")
	title := c.PostForm("title")
	content := c.PostForm("content")

	for i, p := range posts {
		if p.ID == id {
			posts[i].Title = title
			posts[i].Content = content
			c.JSON(http.StatusOK, gin.H{"message": "Post updated successfully"})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Post not found"})
}

func deletePost(c *gin.Context) {
	id := c.Param("id")

	for i, p := range posts {
		if p.ID == id {
			posts = append(posts[:i], posts[i+1:]...)
			c.JSON(http.StatusOK, gin.H{"message": "Post deleted successfully"})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Post not found"})
}
