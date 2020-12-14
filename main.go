package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"log"
	"net/http"
	"server/storage"
	"strings"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	Username  string
	Firstname string
	Lastname  string
}

type loginRequest struct {
	Username  string `json:"username" binding:"required"`
	Password  string `json:"password" binding:"required"`
	PublicKey string `json:"public_key" binding:"required"`
}

var identityKey = "id"

func main() {
	db, err := storage.NewDatabase()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	router := gin.Default()

	mw := createJwtMiddleware(db)

	router.POST("/login", mw.LoginHandler)

	router.NoRoute(mw.MiddlewareFunc(), func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)
		log.Printf("NoRoute claims: %#v\n", claims)
		c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
	})

	authorized := router.Group("/")
	authorized.Use(mw.MiddlewareFunc())
	authorized.Use(signatureVerifierMiddleware(db))
	{
		authorized.GET("/user", userInfo)
		authorized.POST("/refresh", mw.RefreshHandler)
		authorized.POST("/logout", mw.LogoutHandler)
	}

	log.Fatal(router.Run(":8080"))
}

func signatureVerifierMiddleware(db *sql.DB) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		username := jwt.ExtractClaims(ctx)["id"]

		row := db.QueryRow("SELECT public_key FROM users WHERE username == ?", username)

		var public_key string
		if err := row.Scan(&public_key); err != nil {
			log.Fatal(err)
		}

		requestTarget := fmt.Sprintf("(request-target): %s %s", strings.ToLower(ctx.Request.Method), ctx.Request.RequestURI)
		signedHeaderNames := strings.Split(ctx.GetHeader("X-Signed-Headers"), " ")

		signatureData := []string{requestTarget}

		for _, name := range signedHeaderNames {
			value := fmt.Sprintf("%s: %s", name, ctx.GetHeader(name))
			signatureData = append(signatureData, value)
		}

		signatureString := strings.Join(signatureData, "\n")

		res, _ := base64.StdEncoding.DecodeString(public_key)
		buf := bytes.NewBuffer(res)
		r := keyset.NewBinaryReader(buf)
		pub, _ := keyset.ReadWithNoSecrets(r)

		v, err := signature.NewVerifier(pub)
		if err != nil {
			log.Fatal(err)
		}

		inputSignature, err := base64.StdEncoding.DecodeString(ctx.GetHeader("X-Signature"))
		if err != nil {
			log.Fatal(err)
		}

		if err := v.Verify(inputSignature, []byte(signatureString)); err != nil {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": err.Error()})
		}
	}
}

func createJwtMiddleware(db *sql.DB) *jwt.GinJWTMiddleware {
	middleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "][akep",
		Key:         []byte("31337"),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: "id",
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(*User); ok {
				return jwt.MapClaims{
					identityKey: v.Username,
				}
			}
			return jwt.MapClaims{}
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			claims := jwt.ExtractClaims(c)
			return &User{
				Username: claims[identityKey].(string),
			}
		},
		Authenticator: func(c *gin.Context) (interface{}, error) {
			var loginVals loginRequest

			if err := c.ShouldBind(&loginVals); err != nil {
				return "", jwt.ErrMissingLoginValues
			}

			userId := loginVals.Username
			password := loginVals.Password

			if userId == "admin" && password == "admin" {
				insertUserSQL := `INSERT INTO users (username, public_key) VALUES (?, ?) ON CONFLICT (username) DO UPDATE SET public_key=excluded.public_key;`
				statement, err := db.Prepare(insertUserSQL)
				if err != nil {
					log.Fatal(err.Error())
				}

				_, err = statement.Exec(userId, loginVals.PublicKey)
				if err != nil {
					log.Fatal(err.Error())
				}

				return &User{
					Username:  userId,
					Firstname: "Eugene",
					Lastname:  "Belford",
				}, nil
			}

			return nil, jwt.ErrFailedAuthentication
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			if v, ok := data.(*User); ok && v.Username == "admin" {
				return true
			}

			return false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		},
		TimeFunc:      time.Now,
	})

	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	err = middleware.MiddlewareInit()

	if err != nil {
		log.Fatal("JWT Middleware init error: " + err.Error())
	}

	return middleware
}

func userInfo(ctx *gin.Context) {
	claims := jwt.ExtractClaims(ctx)
	ctx.JSON(200, gin.H{
		"userName":   claims[identityKey],
	})
}
