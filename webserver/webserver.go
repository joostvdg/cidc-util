package webserver

import (
	"../model"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
	"text/template"
	"time"
)

// WebserverData is a wrapper for the page title and discovered docker Stacks
type WebserverData struct {
	Title      string
	Containers []model.ContainerInfo
}

// UpdateStacks allows you to update the stacks only
func (wd *WebserverData) UpdateContainers(containers []model.ContainerInfo) {
	wd.Containers = containers
	for _, container := range wd.Containers {
		if container.Name != "" {
			fmt.Printf("  > %s\n", container.String())
		}
	}
}

// HandleGetStacks is the handler function for serving the model.Stacks
func (wd *WebserverData) HandleGetStacks(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(wd.Containers)
}

func (wd *WebserverData) rootHandler(w http.ResponseWriter, r *http.Request) {
	templateRoot := "."
	if len(os.Getenv("TEMPLATE_ROOT")) > 0 {
		templateRoot = os.Getenv("TEMPLATE_ROOT")
	}

	indexLoc := fmt.Sprintf("%s/index.html", templateRoot)
	tmpl := template.Must(template.ParseFiles(indexLoc))
	userAgent := r.Header.Get("User-Agent")
	fmt.Printf("  > [URI: %s, Method: %s, User-Agent: %s]\n", r.RequestURI, r.Method, userAgent)
	tmpl.Execute(w, wd)
}

// Server is a wrapper for the Logger and mux router
type Server struct {
	logger *log.Logger
	mux    *http.ServeMux
}

// StartServer Starts the web server on the given port with the given data
// The data can be refreshed and a next call that is served will return the updated data
// The channel is for graceful shutdown
//   when true is received, graceful shutdown is initiated
//   when graceful shutdown is completed a true is returned
func StartServer(port string, data *WebserverData, c chan bool) {
	router := mux.NewRouter()
	router.HandleFunc("/", data.rootHandler).Methods("GET")
	listenAddress := fmt.Sprintf(":%s", port)
	server := &http.Server{Addr: listenAddress, Handler: router}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	if b := <-c; b {
		fmt.Printf("We got told to quit\n")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		server.Shutdown(ctx)
		cancel()
	}
	c <- true
}
