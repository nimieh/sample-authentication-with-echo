package main

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
)

type User struct {
	Name     string `json:"name" form:"name" query:"name"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

type mcc struct {
	Name string `json:"name"`
	jwt.RegisteredClaims
}

func generateFromPassword(password string, p *params) (encodedHash string, err error) {
	salt, err := generateRandomBytes(p.saltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	// Base64 encode the salt and hashed password.
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Return a string using the standard encoded hash representation.
	encodedHash = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.memory, p.iterations, p.parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func comparePasswordAndHash(password, encodedHash string) (match bool, err error) {
	// Extract the parameters, salt and derived key from the encoded password
	// hash.
	p, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	// Derive the key from the other password using the same parameters.
	otherHash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	// Check that the contents of the hashed passwords are identical. Note
	// that we are using the subtle.ConstantTimeCompare() function for this
	// to help prevent timing attacks.
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}

func decodeHash(encodedHash string) (p *params, salt, hash []byte, err error) {
	//fmt.Println(encodedHash)
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		fmt.Println("err is : ")
		fmt.Println(vals)
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p = &params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.saltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.keyLength = uint32(len(hash))

	return p, salt, hash, nil
}

/*
func register(c echo.Context) error {
	u := User{}

	defer c.Request().Body.Close()

	err := json.NewDecoder(c.Request().Body).Decode(&u)
	if err != nil {
		return err
	}

	fmt.Println(u)
	return c.String(http.StatusOK, u.Name)
}*/

func dataBase() {
	db, err := sql.Open("mysql", "root:b7337a3**@tcp(127.0.0.1:3306)/")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	_, err = db.Exec("CREATE DATABASE IF NOT EXISTS users ")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("USE users ")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec(" CREATE TABLE IF NOT EXISTS user(userName varchar(255) NOT NULL ,password varchar(255) NOT NULL,email varchar(255) NOT NULL );")
	if err != nil {
		panic(err)
	}
}

func post(user User) error {

	p := &params{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   32,
	}

	hash, err := generateFromPassword(user.Password, p)
	if err != nil {
		panic(err)
	}

	db, err := sql.Open("mysql", "root:b7337a3**@tcp(127.0.0.1:3306)/")
	if err != nil {
		panic(err)
	}
	fmt.Println(user.Name + " " + user.Password + " " + user.Email)
	defer db.Close()

	_, err = db.Exec(`USE users`)
	if err != nil {
		panic(err)
	}
	_, err = db.Exec("INSERT INTO user(userName , password , email) VALUES(" + "'" + user.Name + "'" + "," + "'" + hash + "'" + "," + "'" + user.Email + "'" + ");")
	if err != nil {
		panic(err)
	}

	return err
}

func register(c echo.Context) error {
	u := new(User)

	err := c.Bind(u)
	if err != nil {
		return err
	}

	post(*u)

	mySigningKey := []byte("mykey")

	claims := &mcc{
		"Test",
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			ID:        "1",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	ss, err := token.SignedString(mySigningKey)

	return c.String(http.StatusOK, u.Name+" "+u.Password+" "+u.Email+" "+ss)

}

func login(userName, password string, c echo.Context) (bool, error) {

	var pw string

	db, err := sql.Open("mysql", "root:b7337a3**@tcp(127.0.0.1:3306)/")
	if err != nil {
		panic(err)
	}

	defer db.Close()

	_, err = db.Exec(`USE users`)
	if err != nil {
		panic(err)
	}

	rows, err := db.Query(`SELECT password FROM user WHERE userName =  '` + userName + "'")
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		err = rows.Scan(&pw)
	}
	//fmt.Println(pw)

	match, err := comparePasswordAndHash(password, pw)
	if err != nil {
		panic(err)
	}
	//fmt.Print(match)

	if match {

		cookie := new(http.Cookie)
		cookie.Name = "sessionID"
		cookie.Value = strconv.Itoa(5564)
		cookie.Expires = time.Now().Add(1 * time.Minute)
		c.SetCookie(cookie)
		c.String(http.StatusAccepted, "you logged in")
		return true, nil
	} else {
		return false, nil
	}

}

func checkCookie(f echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		cookie, err := c.Cookie("sessionID")
		if err != nil {
			return c.String(http.StatusUnauthorized, err.Error())
		}

		if cookie.Value == "5564" {
			return f(c)
		}

		return c.String(http.StatusUnauthorized, "access denied")
	}

}

func info(c echo.Context) error {
	fmt.Print("done")
	return c.String(http.StatusOK, "you have access ")
}

func jwtTest(c echo.Context) error {
	return c.String(http.StatusOK, "you have access ")
}

func main() {
	dataBase()
	e := echo.New()
	lg := e.Group("/login")
	lg.Use(middleware.BasicAuth(login))
	e.POST("/user", register)
	inf := e.Group("/info")
	inf.Use(checkCookie)
	inf.GET("/test", info)
	jwtgroup := e.Group("jwt")
	jwtgroup.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		SigningMethod: "HS512",
		SigningKey:    []byte("mykey"),
	}))
	jwtgroup.GET("/test", jwtTest)
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})
	e.Logger.Fatal(e.Start(":8000"))
}
