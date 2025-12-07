package main

import (
	"backend/api"

	"github.com/joho/godotenv"
)

func main() {
	// instancier une base de donnée
	
	// charger les variables d'environnement
	godotenv.Load(".env.local")

	// instancier un serveur
	server := api.NewAPIServer("3000")

	// lancer le serveur
	server.Run()
}