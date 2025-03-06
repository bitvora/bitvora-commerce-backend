package main

import (
	"encoding/json"
	"net/http"
)

func JsonResponse(w http.ResponseWriter, status int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := map[string]interface{}{
		"message": message,
		"data":    data,
	}

	json.NewEncoder(w).Encode(response)
}

func HandleHome(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to the API"))
}
