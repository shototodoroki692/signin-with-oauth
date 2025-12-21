package api

import (
	"encoding/json"
	"fmt"
	"testing"
)

var testAppleIdToken string = "eyJraWQiOiJhVmVIRmFXeEFaIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiaG9zdC5leHAuRXhwb25lbnQiLCJleHAiOjE3NjU5NjU4OTMsImlhdCI6MTc2NTg3OTQ5Mywic3ViIjoiMDAwNDAwLjcyYThhMTA0MDQ2ZDRhMTRhNTYwZGEwOTk4NzFiZjJkLjA5NDAiLCJub25jZSI6ImM3ODJkM2Q3LTM2MDktNGM0MS1hZGU2LTg0MjBkZGI1ZDgzNiIsImNfaGFzaCI6InBqQk1GR2RKb0p0OXhhMlhYeGd4ZEEiLCJlbWFpbCI6InRod3NyczQ2ejZAcHJpdmF0ZXJlbGF5LmFwcGxlaWQuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzX3ByaXZhdGVfZW1haWwiOnRydWUsImF1dGhfdGltZSI6MTc2NTg3OTQ5Mywibm9uY2Vfc3VwcG9ydGVkIjp0cnVlfQ.sHlU8WJw__nbmBpO-db06DIzakdcQqwjU516pPW3KD3pNgd6sizZsPnLyusAB0r0SSqrjrwCbS7FTsWeC-jQgO-2SUZC_6Y1SH83blsQfHzWRx85AIcGkR6oeQLXocZ2MTaWPOXP-dg6FsJdwiVcCaem5m4anLRl6aFskjtj2kHSGEki--SMLXo3nv8UjdG6xQIIA647ichDBJ6GBBhUqZwFfAM3eVg58Iv4dNjeqnbkE7zZ-n2CmeIPpuqQVcX-Pasrx8t7BDmo7qd7_1BVY69lEflmHxH8RY7B_JCDH0TdBAnWUKt_qz5ZCE0kfTuGXBCrtylxNfgU7aubPFioGA"
var testKid string = "aVeHFaWxAZ"

func TestGetValidatedAppleIdToken(t *testing.T) {
	idToken, err := getValidatedAppleIdToken(testAppleIdToken)
	if err != nil {
		t.Errorf("erreur lors de la vérification de l'identity token d'Apple:\n%v", err)
	}

	if idToken == nil {
		t.Errorf("l'identity token validé est nil")
	}

	// débug
	fmt.Printf("identity token d'Apple au format jwt.Token:\n%s", testReadableJSON(t, idToken))
}

func TestGetCorrespondingApplePublicKey(t *testing.T) {

	publicKey, err := getCorrespondingApplePublicKey(testKid)
	if err != nil {
		t.Errorf("erreur lors de la récupération de la clé publique rsa correspondant au kid:\n%s", err)
	}

	if publicKey == nil {
		t.Errorf("la clé rsa publique renvoyée n'est pas censée être nil")
	}

	// débug
	fmt.Println("clé publique rsa permettant de vérifier l'identity token:\n", testReadableJSON(t, publicKey))
}

// UTILS

// readableJSON permet de convertir un objet JSON en une chaîne de caractères lisible
//
// la fonction renvoie une string vide si l'erreur renvoyée est non nil
func testReadableJSON(t *testing.T, content any) string {

	bytesData, err := json.Marshal(content)
	if err != nil {
		t.Errorf("impossible d'encoder le contenu json fournit")
	}

	return string(bytesData)
}