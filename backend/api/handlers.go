package api

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// HANDLERS

// tokenRequest définit le format du corps des requêtes de demandes
// de tokens d'autorisation
type tokenRequestBody struct {
	GrantType	string
	ClientId	string
	Platform	string	// indique la plateforme depuis laquelle le client effectue sa requête (web, ios, ...)
	RedirectURI	string
	Code		string	// code d'autorisation fournit par le provider (Apple, Google, etc.)
}

// handleRootRequest traite une réponse à la racine de l'API
func (s *APIServer) handleRootRequest(w http.ResponseWriter, r *http.Request) error {
	// débug
	log.Println("endpoint / atteint !")

	return respondWithJSON(w, http.StatusOK, APIMessage{Message: "success"})
}

// handleAuthorize permet d'autoriser un utilisateur à utiliser notre application
func (s *APIServer) handleAuthorize(w http.ResponseWriter, r *http.Request) error {
	// débug
	fmt.Println("endpoint /auth/authorize atteint !")

	if r.Method != "GET" {
		errorMessage := fmt.Sprintf("Méthode %s non autorisée", r.Method)
		return respondWithError(w, http.StatusBadRequest, errorMessage)
	}

	googleClientId := os.Getenv("GOOGLE_CLIENT_ID")
	if googleClientId == "" {
		return respondWithError(w, http.StatusInternalServerError, "GOOGLE_CLIENT_ID n'est pas définit")
	}

	requestURL := r.URL
	requestQuery := requestURL.Query()

	var idpClientId string
	internalClient := requestQuery.Get("client_id")
	redirectUri := requestQuery.Get("redirect_uri")

	// plateforme depuis laquelle s'authentifie l'utilisateur
	var plateform string

	// définir la plateforme utilisée par l'utilisateur selon redirectUri
	switch redirectUri {
	case os.Getenv("APP_SCHEME"):
		plateform = "mobile"
	case os.Getenv("APP_BASE_URL"):
		plateform ="web"
	default:
		return respondWithError(w, http.StatusBadRequest, "URI de redirection invalide")
	}

	// state permet de conduire la redirection de retour vers la plateforme utilisée
	state := fmt.Sprintf("%s|%s", plateform, requestQuery.Get("state"))

	// définir idpClient selon le provider avec lequel veut s'authentifier
	// l'utilisateur. Le provider est définit par internalClient.
	if internalClient == "google" {
		idpClientId = os.Getenv("GOOGLE_CLIENT_ID")
	} else {
		return respondWithError(w, http.StatusBadRequest, "Provider invalide")
	}

	// créer l'URL de redirection à partir des paramètres
	query := url.Values{}
	query.Set("client_id", idpClientId)
	query.Set("redirect_uri", fmt.Sprintf("%s/auth/callback", os.Getenv("LAN_API_BASE_URL")))
	query.Set("response_type", "code") // permet de définir que nous voulons recevoir le code d'authentification que nous échangeront ensuite contre l'id token
	query.Set("scope", requestQuery.Get("scope")) // ou "identity" si pas de scope (identity permet juste de récupérer les informations de l'utilisateur)
	query.Set("state", state) 
	query.Set("prompt", "select_account") // indique que nous demandons à l'utilisateur de sélectionner son compte Google. Ce paramètre peut être ignoré si nous voulons directement sign-in l'utilisateur

	encodedQuery := query.Encode()
	redirectURL := fmt.Sprintf("%s?%s", os.Getenv("GOOGLE_AUTH_URL"), encodedQuery)

	// renvoyer au client une redirection vers la page d'authentification Google
	http.Redirect(w, r, redirectURL, http.StatusPermanentRedirect)
	return nil
}

// handleCallback permet de recevoir les informations envoyées par Google une
// fois que l'utilisateur s'est authentifié avec Google
//
// Ces informations contiennent le code d'authentification fournit par Google.
func (s *APIServer) handleCallback(w http.ResponseWriter, r *http.Request) error {
	// débug
	fmt.Println("endpoint /auth/callback atteint !")

	if r.Method != "GET" {
		errorMessage := fmt.Sprintf("Méthode %s non autorisée", r.Method)
		return respondWithError(w, http.StatusBadRequest, errorMessage)
	}

	// récupérer les paramètres de la requête
	requestURL := r.URL
	requestQuery := requestURL.Query()

	// récupérer l'état et la plateforme dans la requête
	combinedPlatformAndState := requestQuery.Get("state")
	if combinedPlatformAndState == "" {
		return respondWithError(w, http.StatusBadRequest, "State invalide")
	}

	// récupérer létat et la plateforme séparément
	combinedPlatformAndStateSplited := strings.Split(combinedPlatformAndState, "|")
	if len(combinedPlatformAndStateSplited) < 2 {
		fmt.Println("plateforme et états renvoyés:", combinedPlatformAndState)
		return respondWithError(w, http.StatusBadRequest, "State invalide")
	}

	platform := combinedPlatformAndStateSplited[0]
	state := combinedPlatformAndStateSplited[1]

	// récupérer le code reçu dans la requête
	code := requestQuery.Get("code")

	// créer l'url de redirection vers l'application
	responseQuery := url.Values{}
	responseQuery.Set("code", code)
	responseQuery.Set("state", state)

	encodedResponseQuery := responseQuery.Encode()

	var redirectBaseURL string

	if platform == "web" {
		redirectBaseURL = os.Getenv("APP_BASE_URL")
	} else {
		redirectBaseURL = os.Getenv("APP_SCHEME")
	}

	redirectURL := fmt.Sprintf("%s?%s", redirectBaseURL, encodedResponseQuery)

	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
	return nil
}

// handleToken permet de recevoir le token d'authentification que
// l'utilisateur nous fournit une fois qu'il l'a reçu après s'être 
// authentifié avec Google
func (s *APIServer) handleToken(w http.ResponseWriter, r *http.Request) error {
	// débug
	fmt.Println("endpoint /auth/token atteint !")	
	
	if r.Method != "POST" {
		errorMessage := fmt.Sprintf("Méthode %s non autorisée", r.Method)
		return respondWithError(w, http.StatusBadRequest, errorMessage)
	}

	// récupération des champs du formulaire contenus dans le corps de la requête
	requestBody := &tokenRequestBody{
		r.FormValue("grant_type"),
		r.FormValue("client_id"),
		r.FormValue("platform"),
		r.FormValue("redirect_uri"),
		r.FormValue("code"),
	}

	if requestBody.Code == "" {
		return respondWithError(w, http.StatusBadRequest, "aucun code d'autorisation fournit")
	}

	// préparation de la requête d'obtention de l'id token à Google
	googleRequestURL := "https://oauth2.googleapis.com/token"
	googleRequestContentType := "application/x-www-form-urlencoded"
	googleRequestPayload := url.Values {
		"client_id":		{os.Getenv("GOOGLE_CLIENT_ID")},
		"client_secret": 	{os.Getenv("GOOGLE_CLIENT_SECRET")},
		"redirect_uri": 	{fmt.Sprintf("%s/auth/callback", os.Getenv("LAN_API_BASE_URL"))},
		"grant_type": 		{"authorization_code"},
		"code":				{requestBody.Code},
	}

	googleRequestEncodedPayload := googleRequestPayload.Encode()
	googleRequestBody := strings.NewReader(googleRequestEncodedPayload)

	// envoyer la requête d'obtention de l'id token à Google
	response, err := http.Post(googleRequestURL, googleRequestContentType, googleRequestBody)
	if err != nil {
		log.Println("erreur de l'envoi de la requête à Google:\n", err)
		return err
	}

	googleResponseBody := struct {
		AccessToken	string	`json:"access_token"`
		ExpiresIn	int		`json:"expires_in"`
		Scope		string	`json:"scope"`
		TokenType	string	`json:"token_type"`
		IdToken		string	`json:"id_token"`
	} {}

	responseBodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	response.Body.Close()

	if err := json.Unmarshal(responseBodyBytes, &googleResponseBody); err != nil {
		log.Println("erreur de conversion du corps de la réponse au format json:\n", err)
		return err
	}

	if googleResponseBody.IdToken == "" {
		return respondWithError(w, http.StatusBadRequest, "Aucun Id token reçu de Google")
	}

	// récupérer les informations contenues dans l'id token
	data, err := getIdTokenClaims(googleResponseBody.IdToken)
	if err != nil {
		return err
	}

	accessToken, err := generateAccessToken(data.GivenName, data.Email, data.EmailVerified)
	if err != nil {
		return err
	}

	// Si besoin générer le refresh token ici

	// si le client est sur le web, stocker le token d'accès dans les cookies
	if requestBody.Platform == "web" {

		// générer la date d'expiration du cookie
		expiresAt, err := generateExpirationDate(os.Getenv("COOKIE_LIFETIME"))
		if err != nil {
			return err
		}

		maxAge, err := strconv.Atoi(os.Getenv("COOKIE_LIFETIME"))
		if err != nil {
			return err
		}

		// générer le corps de la réponse renvoyée
		responseData := struct{
			Success		bool		`json:"success"`
			IssuedAt	time.Time	`json:"issued_at"`
			ExpiresAt	time.Time	`json:"expires_at"`
		}{
			true,
			time.Now().UTC(),
			*expiresAt,
		}

		// définir le cookie que nous renvoyons au client
		cookie := http.Cookie{
			Name:			"access_token",
			Value:			*accessToken,
			Quoted:			true,

			Path:			"/",
			Expires:		*expiresAt,

			MaxAge:			maxAge,
			Secure:			true,
			HttpOnly:		true,
			// SameSite:		http.S,
			Partitioned:	false,
			Raw:			"jsais_pas",
			Unparsed:		[]string{"random"},
		}

		// ajouter notre cookie au header de la réponse
		http.SetCookie(w, &cookie)

		return respondWithJSON(w, http.StatusOK, responseData)
	}

	// renvoyer notre token d'accès au client
	return respondWithJSON(w, http.StatusOK, *accessToken)
}

// handleSession permet de récupérer les informations de la session de l'utilisateur
//
// NOTE: ce endpoint n'est utilisé que pour les clients web
func (s *APIServer) handleSession(w http.ResponseWriter, r *http.Request) error {

	fmt.Println("endpoint /auth/session atteint !")
	
	// vérifier qu'il s'agit bien d'une requête GET
	if r.Method != "GET" {
		return respondWithError(w, http.StatusBadRequest, "mauvaise méthode utilisée")
	}

	// obtenir le cookie depuis la réponse
	cookie, err := r.Cookie("access_token")
	if err != nil {
		log.Println("erreur de récupération du cookie de session:\n", err)
		return err
	}

	// récupérer l'access token stocké dans le cookie
	accessToken := cookie.Value

	// vérifier l'access token et en récupérer les claims s'il est authentique
	claims, err := getVerifiedAccessToken(accessToken)	
	if err != nil {
		log.Println("erreur de vérification du token d'accès:\n", err)
		return err
	}

	// générer la corps de la réponse
	responseData :=  struct {
		User				accessTokenClaims
		CookieExpiration	time.Time
	} {
		*claims,
		cookie.Expires,
	}

	return respondWithJSON(w, http.StatusOK, responseData)
}

// handleSignout permet de déconnecter un utilisateur
//
// NOTE: cette méthode n'est utile que pour les clients web, car nous supprimons
// leur cookie d'accès. Le traitement de la déconnexion pour un client natif se
// fait ici uniquement côté client
func (s *APIServer) handleSignout(w http.ResponseWriter, r *http.Request) error {

	fmt.Println(" endpoint /auth/signout atteint !")

	if r.Method != "POST" {
		return respondWithError(w, http.StatusMethodNotAllowed, "méthode non autorisée")
	}

	// créer le cookie
	cookie := http.Cookie{
		Name:			"access_token",
		Value:			"",
		Quoted:			true,

		Path:			"/",
		Expires:		time.Now().UTC(),

		MaxAge:			0, // supprime le cookie instantanément
		Secure:			true,
		HttpOnly:		true,
		// SameSite:		http.S,
		// Partitioned:	false,
		// Raw:			"jsais_pas",
		// Unparsed:		[]string{"random"},
	}

	// retirer le cookie d'accès
	//
	// Vérifier que cette méthode de suppression du cookie est valide lorsque le
	// client web fonctionnera correctement (actuellement blocké par les CORS policy)
	http.SetCookie(w, &cookie)

	// supprimer le refresh token des cookies si nous en avons un

	return respondWithJSON(w, http.StatusOK, APIMessage{"signed-out"})
}

// handleData permet de récupérer des données protégées côté client
//
// Ce handler est protégé par un middleware qui vérifie que l'utilisateur est
// correctement authentifié
func (s *APIServer) handleData(w http.ResponseWriter, r *http.Request) error {

	fmt.Println("endpoint /protected/data atteint !")

	if r.Method != "GET" {
		return respondWithError(w, http.StatusMethodNotAllowed, "methode non autorisée")
	}

	// récupérer le contexte
	ctx := r.Context()
	claims, ok := ctx.Value("user").(*accessTokenClaims)

	if !ok {
		log.Println("les claims récupérés dans le contexte ne sont pas de la forme *accessTokenClaims")
		respondWithError(w, http.StatusInternalServerError, "internal-server-error")
	}

	// préparer la réponse
	response := struct {
		PrivateMessage	string		`json:"private_message"`
		UserEmail		string		`json:"user_email"`
		UserName		string  	`json:"username"`
		Date			time.Time	`json:"date"`
	} {
		"Ceci est un message privé, ne le répète à personne",
		claims.Name,
		claims.Email,
		time.Now(),
	}

	// renvoyer la réponse
	return respondWithJSON(w, http.StatusOK, response)
}

// appleAuthRequest définit le contenu du corps d'une requête d'authentification
// avec Apple
type appleAuthRequest struct {
	IdentityToken	string	`json:"id_token"`
	RawNonce		string	`json:"raw_nonce"`
	GivenName		*string	`json:"given_name,omitempty"`
	FamilyName		*string	`json:"family_name,omitempty"`
	Email			*string	`json:"email,omitempty"`
}

// appleIdTokenClaims définit les claims que contient l'identity token fournit par
// Apple pour identifier un utilisateur authentifié avec Apple
type appleIdTokenClaims struct {
	Nonce			string	`json:"nonce"`
	CHash			string	`json:"c_hash"`
	Email			string	`json:"email"`
	EmailVerified	bool	`json:"email_verified"`
	IsPrivateEmail	bool	`json:"is_private_email"`	
	jwt.RegisteredClaims
}

// handleAppleIOS permet de traiter les demandes d'authentification d'un 
// utilisateur avec son compte Apple depuis un client IOS
func (s *APIServer) handleAppleIOS(w http.ResponseWriter, r *http.Request) error {
	
	fmt.Println("endpoint /auth/apple/ios atteint !")

	if r.Method != "POST" {
		return respondWithError(w, http.StatusMethodNotAllowed, "méthode non autorisée")
	}

	var requestBodyAny any
	
	// récupérer le corps de la requête au format json décodé
	if err := json.NewDecoder(r.Body).Decode(&requestBodyAny); err != nil {
		return respondWithError(w, http.StatusBadRequest, "mauvaise requête")
	}

	// débug
	requestBodyStr, err := readableJSON(requestBodyAny)
	if err != nil {
		return err
	}

	fmt.Println("corps de la requête envoyée pour l'authentification avec Apple:\n", requestBodyStr)
	// fin du débug

	requestBody, ok := requestBodyAny.(appleAuthRequest)
	if !ok {
		log.Println("le corps de la requête ne correspond pas au format appleAuthRequest")
		return respondWithError(w, http.StatusBadRequest, "mauvaise requête")
	}

	// ATTENTION:
	// Il faut vérifier auprès d'apple que les données fournies par le client sont valides
	// avant de renvoyer notre accès token.
	// 
	// TODO: 
	// Implémenter la logique de vérification par Apple des données reçues

	// générer un token d'accès pour l'utilisateur
	accessToken, err := generateAccessToken(*requestBody.GivenName, *requestBody.Email, true)
	if err != nil {
		return err
	}

	// créer le corps de la réponse renvoyée à l'utilisateur
	responseBody := struct {
		AccessToken	string	`json:"access_token"`
	} {
		*accessToken,
	}

	// renvoyer la réponse
	return respondWithJSON(w, http.StatusOK, responseBody)
}

// verifyAndCreateAccessToken permet de vérifier les informations fournies par le client
// lors d'une demande d'authentification avec Apple, et renvoi un access token si les
// informations sont correctes
//
// NOTE:
// Afin de vérifier l'identity token reçu du client nous devons:
// 1. Vérifier la signature JWS E256 en utilisant la clé publique de notre serveur
// 2. Vérifier le nonce utilisé pour l'authentification
// 3. Vérifier que le champs contient https://appleid.apple.com
// 4. Vérifier que le champs "aud" correspond à notre client_id de développeur
// 5. Vérifier que la date d'expiration du token "exp" n'est pas dépassée
//
// voir https://developer.apple.com/documentation/signinwithapple/verifying-a-user
func verifyAndCreateAccessToken(data appleAuthRequest) (*string, error) {

	// vérifier s'il s'agit de la première demande d'authentification avec Apple
	isFirstSigninWithApple := false
	if data.Email != nil && data.GivenName != nil {
		isFirstSigninWithApple = true
	} 

	fmt.Println(isFirstSigninWithApple)

	// 1. Vérifier la signature JWS E256 en utilisant la clé publique de notre serveur
	// // vérifier la signature du de l'identity token
	// idToken, ok := getValidatedAppleIdToken(data.IdentityToken)

	// 2. Vérifier le nonce utilisé pour l'authentification
	// 3. Vérifier que le champs contient https://appleid.apple.com
	// 4. Vérifier que le champs "aud" correspond à notre client_id de développeur
	// 5. Vérifier que la date d'expiration du token "exp" n'est pas dépassée

	return nil, nil
}

// appleJWK (JSON Web Key) représente une clé publique utilisée pour vérifier les
// identity tokens délivrés par Apple
type appleJWK struct {
	Alg	string	`json:"alg"`	// algorithme utilisé pour encrypter le token
	E	string	`json:"e"`		// valeur de l'exposant pour la clé publique RSA
	Kid	string	`json:"kid"`	// identifiant de la clé
	Kty	string	`json:"kty"`	// paramétrage du type de clé (doit être "RSA")
	N	string	`json:"n"`		// valeur de la clé publique RSA
	Use	string	`json:"use"`	// l'utilisation attendue de la clé publique
}

// appleJWKSet (JSON Web Key Set) représente une liste d'objets JWK (JSON Web Key)
type appleJWKSet struct {
	Keys	[]appleJWK	`json:"keys"`
}

// getValidatedAppleIdToken permet d'obtenir l'identity token transmit par
// Apple à l'utilisateur vérifié, au format *jwt.Token
func getValidatedAppleIdToken(idTokenStr string) (*jwt.Token, error) {
	
	return jwt.ParseWithClaims(idTokenStr, &appleIdTokenClaims{}, func(token *jwt.Token) (any, error) {
		return getAppleIdTokenPublicKey(token)
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
}	

// getAppleIdTokenPublicKey permet de récupérer la clé publique permettant de
// valider la signature de l'identity token d'Apple.
//
// La fonction renvoie un pointeur sur la clé publique rsa si l'erreur renvoyée
// est non-nil.
func getAppleIdTokenPublicKey(idToken *jwt.Token) (*rsa.PublicKey, error) {

	// récupérer le kid du token
	kid, ok := idToken.Header["kid"]
	if !ok {
		return nil, errors.New("aucun kid trouvé dans le header de l'identity token d'Apple")
	}

	// convertir le kid au format string
	kidStr, ok := kid.(string)
	if !ok {
		return nil, fmt.Errorf("impossible de convertir le kid suivant au format string: %s", kid)
	}

	// récupérer la clé publique de signature de l'idToken avec le kid
	return getCorrespondingApplePublicKey(kidStr)
}

// getCorrespondingApplePublicKey permet d'obtenir la clé publique de signature de
// l'identity token correspondant au kid que nous fournissons.
//
// La fonction renvoie un pointeur nil sur la clé publique rsa si l'erreur renvoyée
// est non-nil.
func getCorrespondingApplePublicKey(kid string) (*rsa.PublicKey, error) {
	
	// récupérer la liste de JWK d'Apple
	JWKSet, err := getAppleJWKSet()
	if err != nil {
		return nil, err
	}

	// renvoyer la clé publique si l'une d'elle correspond à notre kid
	for _, key := range JWKSet.Keys {
		if key.Kid == kid {
			
			// créer une clé publique rsa.PublicKey d'après les données de la clé JWK
			return jwkToRSAPublicKey(key)
		}
	}

	// renvoyer une erreur si aucune clé publique ne correspond à notre kid
	return nil, fmt.Errorf("aucune clé publique pour le kid: %s", kid)
}

// getAppleJWKSet permet de récupérer les clés JWK utilisées par Apple
//
// la fonction renvoi un JWKSet nil seulement si l'erreur renvoyée est
// non nil
func getAppleJWKSet() (*appleJWKSet, error) {
	
	// récupérer les clés publiques de signature des jwt Apple
	res, err := http.Get("https://appleid.apple.com/auth/keys")
	if err != nil {
		log.Println("échec de la récupération du JWKSet d'Apple:\n", err)
		return nil, err
	}

	JWKSet := new(appleJWKSet)

	err = json.NewDecoder(res.Body).Decode(JWKSet)
	if err != nil {
		return nil, err
	}

	return JWKSet, nil
}

// jwkToRSAPublicKey permet de convertir une clé JWK au format rsa.PublicKey.
//
// La fonction renvoie un pointeur nil correspondant à la clé publique rsa
// seulement si l'erreur renvoyée est non-nil.
func jwkToRSAPublicKey(JWK appleJWK) (*rsa.PublicKey, error) {

	decodedN, err := convertBase64urlUIntToBigInt(JWK.N)
	if err != nil {
		return nil, err
	}

	decodedE, err := convertBase64urlUIntToBigInt(JWK.E)
	if err != nil {
		return nil, err
	}

	rsaPublicKey := &rsa.PublicKey{
		N:	decodedN,
		E:	int(decodedE.Int64()),
	}

	return rsaPublicKey, nil
}

// convertBase64urlUIntToBigInt permet de récupérer l'entier correspondant au
// paramètre de la clé publique rsa en encodé sous la forme de valeur Base64urlUInt
//
// La fonction renvoie un pointeur nil sur un big.Int seulement si l'erreur
// renvoyée est non-nil
func convertBase64urlUIntToBigInt(encodedStr string) (*big.Int, error) {

	// décoder la chaîne de caractères encodée reçue 
	buf, err := base64.RawURLEncoding.DecodeString(encodedStr)
	if err != nil {
		log.Println("erreur de décodage de la string encodée en base64urlUInt:\n", err)
		return nil, err
	}

	// convertir le buffer contenant les informations décodées format []byte 
	// au format big.Int.
	decodedUInt := new(big.Int).SetBytes(buf)

	return decodedUInt, nil
}

// UTILS

// readableJSON permet de convertir un objet JSON en une chaîne de caractères lisible
//
// la fonction renvoie une string vide si l'erreur renvoyée est non nil
func readableJSON(content any) (string, error) {

	bytesData, err := json.Marshal(content)
	if err != nil {
		log.Println("erreur de récupération du json au format []bytes:\n", err)
		return "", err
	}

	return string(bytesData), nil
}