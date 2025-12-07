package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

// APIServer représente un serveur d'API
type APIServer struct {
	listenPort	string
	// database	
}

// NewAPIServer instancie un serveur d'API
func NewAPIServer(listenPort string) *APIServer {
	return &APIServer{
		listenPort:	listenPort,
	}
}

// Run permet de lancer notre serveur d'API
func (s *APIServer) Run() {
	// instanciation d'un router mux
	router := mux.NewRouter();

	// routes de notre API
	router.HandleFunc("/", makeErrorHandler(s.handleRootRequest))
	router.HandleFunc("/auth/authorize", makeErrorHandler(s.handleAuthorize))
	router.HandleFunc("/auth/callback", makeErrorHandler(s.handleCallback))
	router.HandleFunc("/auth/token", makeErrorHandler(s.handleToken))

	// débug
	log.Printf("lancement sur serveur d'API sur le port n°%s ...\n", s.listenPort)

	// exécution de notre serveur d'API
	if err := http.ListenAndServe(":"+s.listenPort, router); err != nil {
		log.Printf("erreur lors de l'exécution du serveur:\n%v\n", err)
	}
}

// APIHandler correspond à la forme des handlers de l'API
type APIHandler func(w http.ResponseWriter, r *http.Request) error

// makeErrorHandler traite les erreur renvoyées par les handlers
func makeErrorHandler(f APIHandler) func(w http.ResponseWriter, r *http.Request) {
	return func (w http.ResponseWriter, r *http.Request) {
		// traitement de l'erreur renvoyée par le handler
		if err := f(w, r); err != nil {
			// débug
			log.Println("erreur survenue:\n", err)

			respondWithError(w, http.StatusInternalServerError, "internal-server-error")
		}
	}
}

// respondWithJSON permet de renvoyer du JSON en réponse au client
func respondWithJSON(w http.ResponseWriter, status int, content any) error {
	// définition de l'en-tête de la réponse
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)

	// renvoyer le contenu au format JSON
	return json.NewEncoder(w).Encode(content)
}

// respondWithError permet de renvoyer une erreur en réponse au client
func respondWithError(w http.ResponseWriter, status int, message string) error {
	return respondWithJSON(w, status, APIError{Error: message})
}

// APIMessage correspond au format d'un message renvoyé par notre API au client
type APIMessage struct {
	Message	string	`json:"message"`;
}

// APIError correspond au format d'une erreur renvoyé par notre API au client
type APIError struct {
	Error	string	`json:"error"`;
}