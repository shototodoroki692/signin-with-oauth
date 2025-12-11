package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

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

	// Plateforme depuis laquelle s'authentifie l'utilisateur
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

	accessToken, err := generateAccessToken(*data)
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

		// débug
		responseBytes, err := json.Marshal(responseData)
		if err != nil {
			return err
		}
		fmt.Println("réponse renvoyée au client web:\n", string(responseBytes))
		// fin du débug

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
	claims := ctx.Value("user").(*accessTokenClaims)

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