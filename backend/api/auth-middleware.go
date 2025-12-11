package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// authMiddleware permet de vérifier qu'un utilisateur est authentifié
// (en vérifiant et validant son token d'accès) avant de l'autoriser à
// accéder à un endpoint de notre API
func (s *APIServer) authMiddleware(next http.HandlerFunc) (http.HandlerFunc) {
	return func (w http.ResponseWriter, r *http.Request) {
		
		// débug
		fmt.Println("dans le middleware d'autorisation")

		var accessToken string

		// Pour les clients natifs: récupérer l'access token depuis le header
		header := r.Header
		authorization := header.Get("Authorization")

		if authorization != "" {
			// traitement si le header d'autorisation n'est pas vide (client natif)
			fields := strings.Fields(authorization)

			// débug
			fmt.Println("champs du headers Authorization:", fields)

			if fields[0] != "Bearer" {
				log.Println("Header Authorization <Bearer> manquant dans la requête")
				respondWithError(w, http.StatusUnauthorized, "Header Authorization <Bearer> manquant dans la requête")
				return
			}

			accessToken = fields[1]
		} else {
			// traitement si le header d'autorisation est vide (client web)
			cookie, err:= r.Cookie("access_token")
			if err != nil {
				log.Println("Impossible d'accéder au cookie access_token:\n", err)
				respondWithError(w, http.StatusUnauthorized, "cookies unavailable")
				return
			}

			accessToken = cookie.Value
		}

		if accessToken == "" {
			log.Println("aucun token d'accès fournit")
			respondWithError(w, http.StatusUnauthorized, "aucun token d'accès fournit")
			return
		}

		// valider et vérifier l'access token
		claims, err := getVerifiedAccessToken(accessToken)
		if err != nil {
			log.Println("access token invalide")
			respondWithError(w, http.StatusUnauthorized, "access token invalide")	
			return
		}

		// appeler le handler en lui fournissant en contexte les informations
		// de l'utilisateur
		ctx := context.WithValue(r.Context(), "user", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}