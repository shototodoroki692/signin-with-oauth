package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
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

	// débug
	// fmt.Printf("corps de la requête: %q\ntype de la requête: %T\n", r.Body, r.Body)
	// bodyBytes, err := io.ReadAll(r.Body)
	// if err != nil {
	// 	log.Println("impossible de lire le corps de la requête:\n", err)
	// 	return err
	// }

	// r.Body.Close()

	// fmt.Printf("coprs de la requête reçu:\n%s\n", bodyBytes)
	// fin du débug

	// récupération des champs du formulaire contenus dans le corps de la requête
	requestBody := &tokenRequestBody{
		r.FormValue("grant_type"),
		r.FormValue("client_id"),
		r.FormValue("platform"),
		r.FormValue("redirect_uri"),
		r.FormValue("code"),
	}

	// débug
	fmt.Println("corps de la requête:\n", requestBody)

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

	// débug
	fmt.Println("\ncorps de la requête envoyée à Google:\n", googleRequestBody)

	// envoyer la requête d'obtention de l'id token à Google
	response, err := http.Post(googleRequestURL, googleRequestContentType, googleRequestBody)
	if err != nil {
		log.Println("erreur de l'envoi de la requête à Google:\n", err)
		return err
	}

	// débug
	// fmt.Printf("\nréponse reçue de Google:\n%v\n", *response)
	// bodyBytes, err := io.ReadAll(response.Body)
	// if err != nil {
	// 	return err
	// }
	// fmt.Printf("\ncorps de la réponse:\n%v\n", string(bodyBytes))
	// fin du débug

	// récupérer la réponse au formar json
	// var responseBodyBuffer bytes.Buffer
	// var responseBodyAny any
	responseBody := struct {
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

	responseBodyBuf := bytes.NewBuffer(responseBodyBytes)
	
	// débug
	fmt.Printf("\nréponse renvoyée par Google (buffer):\n%v\n", responseBodyBuf)

	// récupérer l'id token renvoyé par Google
	// if err := json.NewDecoder(responseBodyBuf).Decode(&responseBody); err != nil {
	// 	log.Println("erreur de récupération du corps de la réponse:\n", err)
	// 	return err
	// }

	if err := json.Unmarshal(responseBodyBytes, &responseBody); err != nil {
		log.Println("erreur de conversion du corps de la réponse au format json:\n", err)
		return err
	}

	// débug
	fmt.Printf("\nréponse reçue:\n%v\n", responseBody)

	if responseBody.IdToken == "" {
		return respondWithError(w, http.StatusBadRequest, "Aucun Id token reçu de Google")
	}

	// débug
	// fmt.Println("réponse renvoyée par Google:\n", responseBody)
	fmt.Println("id token renvoyé:\n", responseBody.IdToken)

	// récupérer les informations contenues dans l'id token
	data, err := getIdTokenClaims(responseBody.IdToken)
	if err != nil {
		return err
	}

	// TODO:
	// Stocker les données renvoyées dans l'id token dans notre base de données

	// NOTE:
	// Lui il renvoie toutes les infos avec la librairie jose

	accessToken, err := generateAccessToken(*data)
	if err != nil {
		return err
	}

	fmt.Println("\naccess token généré:\n", *accessToken)

	// Si besoin générer le refresh token ici

	// si le client est sur le web, stocker le token d'accès dans les cookies
	if requestBody.Platform == "web" {
		fmt.Println("TODO: traiter la réponse pour un client web")
	}

	// renvoyer notre token d'accès au client
	return respondWithJSON(w, http.StatusOK, *accessToken)
}