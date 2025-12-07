package api

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

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
	
	// débug
	fmt.Println("url saisie par le client:\n", requestURL)

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

	// débug
	fmt.Println("url vers laquelle est redirigé l'utilisateur:\n", redirectURL)

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

	// TODO: implémenter la,logique de traitement du token

	return nil
}