package api

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// accessTokenClaims contient les claims contenus dans l'access token
// généré et renvoyé au client par notre backend. En plus de contenir
// les registered claims, il contient également certaines informations
// sur l'utilisateur.
type accessTokenClaims struct {
	UserId			string	`json:"user_id"`
	Email			string	`json:"email"`
	EmailVerified	bool	`json:"email_verified"`
	Name			string	`json:"name"`
	jwt.RegisteredClaims
}

// idTokenClaims contient les claims contenus dans l'id token que renvoi Google
// lors de la demande des informations concernant un utilisateur
type idTokenClaims struct {
	Azp				string	`json:"azp"`
	Email			string	`json:"email"`
	EmailVerified	bool	`json:"email_verified"`
	FamilyName		string	`json:"family_name"`
	GivenName		string	`json:"given_name"`
	Name			string	`json:"name"`
	Picture			string	`json:"picture"`
	jwt.RegisteredClaims
}

// generateAccessToken permet de générer un token d'accès
//
// Un pointeur nil sur le token de d'accès est renvoyé uniquement si l'erreur
// renvoyée n'est pas nil
func generateAccessToken(userData idTokenClaims) (*string,error) {

	// débug
	fmt.Println("demande de génération d'un token d'accès")

	// générer la date d'expiration de l'acces token
	expirationDate, err := generateExpirationDate(os.Getenv("ACCESS_TOKEN_LIFETIME"))
	if err != nil {
		return nil, err
	}

	// définir le payload du token d'accès
	claims := accessTokenClaims{
		"user_id_backend_defined",
		userData.Email,
		userData.EmailVerified,
		userData.Name,
		jwt.RegisteredClaims {
			Issuer:		"signin-with-oauth",
			IssuedAt:	jwt.NewNumericDate(time.Now().UTC()),
			ExpiresAt:	jwt.NewNumericDate(*expirationDate),
		},
	}

	// récupérer la clé de signature du token
	accessTokenSecret := os.Getenv("ACCESS_TOKEN_SECRET")

	// générer le token d'accès (JWT)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(accessTokenSecret))

	if err != nil {
		log.Println("erreur de signature du token d'accès:\n", err)
		return nil, err
	}

	// retourner le token d'accès signé
	return &signedToken, nil
}

// getIdTokenClaims permet de récupérer les revendications de l'id token
// renvoyé par Google donné au format string
//
// La fonction renvoie un pointeur nil sur idTokenClaims seulement si l'erreur
// renvoyée est non nil
func getIdTokenClaims(tokenStr string) (*idTokenClaims, error) {
	
	// récupérer le token id sous la forme *jwt.Token
	token, _, err := jwt.NewParser().ParseUnverified(tokenStr, &idTokenClaims{})
	if err != nil {
		log.Println("erreur de récupération des claims de l'id token")
		return nil, err
	}

	// récupérer les claims sous la forme *idTokenClaims
	claims, ok := token.Claims.(*idTokenClaims)
	if !ok {
		log.Println("Les claims de l'id token renvoyé par Google ne correpondent pas:\n", token.Claims)
		return nil, fmt.Errorf("invalid-id-token-claims")
	}

	return claims, nil
}

// getVerifiedAccessToken permet d'obtenir les claims du token d'accès
// seulement s'il n'a pas été falsifié.
//
// La fonction renvoi un pointeur nil sur un les claims du token d'accès 
// seulement si l'erreur renvoyée n'est pas nulle
func getVerifiedAccessToken(accessTokenStr string) (*accessTokenClaims, error) {

	accessTokenSecret := os.Getenv("ACCESS_TOKEN_SECRET")

	// renvoyer le l'access token parsé, validé et vérifié
	token, err := jwt.ParseWithClaims(accessTokenStr, &accessTokenClaims{}, func(token *jwt.Token) (any, error) {
		return []byte(accessTokenSecret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*accessTokenClaims)
	if !ok {
		return nil, fmt.Errorf("le type de claims n'est pas reconnu")
	}

	return claims, nil
}

// generateExpirationDate permet de générer une date d'expiration au format
// time.Time en prenant en paramètre une durée de vie en secondes (au format
// string).
//
// La fonction renvoie un pointeur nil sur la date d'expiration seulement si
// l'erreur renvoyée n'est pas nil
func generateExpirationDate(lifetimeStr string) (*time.Time, error) {

	lifetime, err := convertSecondsStrToDuration(lifetimeStr)
	if err != nil {
		return nil, err
	}

	// renvoyer la date d'expiration
	expirationDate := time.Now().Add(*lifetime).UTC()
	return &expirationDate, nil
}

// convertSecondsStrToDuration converti une durée exprimée en secondes (au format string)
// en durée exprimée en secondes (au format time.Time)
// 
// La fonction renvoie un pointeur nil sur la durée seulement si l'erreur
// renvoyée n'est pas nil
func convertSecondsStrToDuration(secondsStr string) (*time.Duration, error) {

	// convertir la durée fournie au format int64
	seconds, err := strconv.ParseInt(secondsStr, 10, 64)
	if err != nil {
		return nil, err
	}

	duration := time.Duration(seconds) * time.Second
	return &duration, nil
}