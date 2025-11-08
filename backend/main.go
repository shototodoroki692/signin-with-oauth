package main

import "backend/api"

func main() {
	// instancier une base de donnée

	// instancier un serveur
	server := api.NewAPIServer("3000")

	// lancer le serveur
	server.Run()
}