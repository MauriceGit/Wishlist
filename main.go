package main

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

type Todo struct {
	Name     string
	IsDone   bool
	ImageUrl string
}

var (
	defaultImage = "https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fget.pxhere.com%2Fphoto%2Fplant-fruit-food-produce-banana-healthy-eat-single-fruits-diet-vitamins-flowering-plant-land-plant-banana-family-cooking-plantain-1386949.jpg&f=1&nofb=1&ipt=756f2c2f08e9e3d1179ece67b7cb35e273fb41c12923ddeaf5b46527e2c62c4b&ipo=images"
	todos        = []Todo{
		{"Learn Go", false, defaultImage},
		{"Write a Go web app", false, defaultImage},
		{"Test the app", false, defaultImage},
	}
	mu sync.Mutex
	//tmpl = template.Must(template.ParseFiles("templates/todo.html", "templates/todo-item.html"))

	tmplTodo = template.Must(template.ParseFiles("templates/todo.html"))
	tmplItem = template.Must(template.ParseFiles("templates/todo-item.html"))
)

// Handler for rendering the full list
func todoListHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	// Render the full list
	fmt.Println("Reload page")
	if err := tmplTodo.Execute(w, todos); err != nil {
		fmt.Println(err)
	}
}

// Handler to toggle todo item
func toggleTodoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		mu.Lock()
		defer mu.Unlock()

		// Retrieve the todo index from the form value
		todoIdx := r.FormValue("index")
		state := r.FormValue("checked")

		// Parse todo index to an integer
		idx, err := strconv.Atoi(todoIdx)
		if err == nil && idx >= 0 && idx < len(todos) {
			// Update the todo state (state is "true" when checked)
			todos[idx].IsDone = (state == "true")
			fmt.Printf("Set todo '%v' to %v\n", todos[idx].Name, todos[idx].IsDone)
		}

		// Manual check for HTMX request using the HX-Request header
		if r.Header.Get("HX-Request") == "true" {
			// Send back the updated todo item only (partial update)
			if err := tmplItem.Execute(w, struct {
				Index int
				Todo  Todo
			}{
				Index: idx,
				Todo:  todos[idx],
			}); err != nil {
				fmt.Println(err)
			}

			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	fmt.Println("Received image!")

	// Parse multipart form data
	r.ParseMultipartForm(10 << 20) // 10MB limit

	// Get the image file from the request
	file, handler, err := r.FormFile("image")
	if err != nil {
		fmt.Println("Error retrieving file:", err)
		return
	}
	defer file.Close()

	// Save the file to the server
	filePath := filepath.Join("uploads", handler.Filename)
	dst, err := os.Create(filePath)
	if err != nil {
		fmt.Println("Error saving file:", err)
		return
	}
	defer dst.Close()

	_, err = dst.ReadFrom(file)
	if err != nil {
		fmt.Println("Error copying file:", err)
		return
	}

	// Update the corresponding todo item with the image URL
	index := r.FormValue("index")
	if idx, err := strconv.Atoi(index); err == nil && idx < len(todos) {
		todos[idx].ImageUrl = "/" + filePath // Update the ImageUrl field
		fmt.Printf("Saved image as %v\n", todos[idx].ImageUrl)
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {
	http.HandleFunc("/", todoListHandler)
	http.HandleFunc("/toggle", toggleTodoHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.ListenAndServe(":8080", nil)

}
