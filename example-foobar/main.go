package main

import (
	"io/ioutil"
	"log"
	"net/http"
)

func foobar(input string) {
	log.Printf("Got input: %s", input)
}

func foobarHandler(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Could not read request body"))
	}

	foobar(string(body))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("You did it!"))
}

func main() {
	http.HandleFunc("/foobar", foobarHandler)

	log.Println("Listening on http://localhost:6001/foobar")
	log.Fatal(http.ListenAndServe(":6001", nil))
}
