package main

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"sync"
)

type Todo struct {
	Name     string
	IsDone   bool
	ImageUrl string
}

type TemplateTodo struct {
	Index int
	Todo  Todo
}

var (
	defaultImage = "https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fget.pxhere.com%2Fphoto%2Fplant-fruit-food-produce-banana-healthy-eat-single-fruits-diet-vitamins-flowering-plant-land-plant-banana-family-cooking-plantain-1386949.jpg&f=1&nofb=1&ipt=756f2c2f08e9e3d1179ece67b7cb35e273fb41c12923ddeaf5b46527e2c62c4b&ipo=images"
	todos        = []Todo{
		{"Learn Go", false, defaultImage},
		{"Write a Go web app", true, defaultImage},
		{"Test the app", false, defaultImage},
	}
	mu sync.Mutex
	//tmpl = template.Must(template.ParseFiles("templates/todo.html", "templates/todo-item.html"))

	tmplTodo = template.Must(template.ParseFiles("templates/todo.html"))
	//tmplEdit = template.Must(template.ParseFiles("templates/todo-edit.html"))
)

func parseId(id string) int {
	idx, err := strconv.Atoi(id)
	if err != nil || idx < 0 || idx >= len(todos) {
		fmt.Printf("Parsing the id '%v' results in err '%v' or an index that is out-of-bounds\n", id, err)
	}
	return idx
}

// Handler for rendering the full list
func todoListHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	data := make([]TemplateTodo, len(todos))
	for i, t := range todos {
		data[i].Index = i
		data[i].Todo = t
	}

	if err := tmplTodo.ExecuteTemplate(w, "all", data); err != nil {
		fmt.Println(err)
	}

}

// Handler to toggle todo item
func reserveTodoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		idx := parseId(r.PathValue("id"))

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		mu.Lock()
		defer mu.Unlock()

		reserve := r.FormValue("reserve") == "true"
		todos[idx].IsDone = reserve

		if r.Header.Get("HX-Request") == "true" {
			if err := tmplTodo.ExecuteTemplate(w, "todo-item", struct {
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

func itemHandler(w http.ResponseWriter, r *http.Request) {
	//tmplItem := template.Must(template.ParseFiles("templates/todo-item.html"))

	fmt.Println("Handle item!")

	if r.Method == http.MethodGet {
		idx := parseId(r.PathValue("id"))

		mu.Lock()
		defer mu.Unlock()

		if r.Header.Get("HX-Request") == "true" {
			if err := tmplTodo.ExecuteTemplate(w, "todo-item", struct {
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

func editHandler(w http.ResponseWriter, r *http.Request) {
	tmplEdit := template.Must(template.ParseFiles("templates/todo-edit.html"))

	if r.Method == http.MethodGet {
		idx := parseId(r.PathValue("id"))

		mu.Lock()
		defer mu.Unlock()

		if r.Header.Get("HX-Request") == "true" {
			if err := tmplEdit.Execute(w, TemplateTodo{
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

func editDoneHandler(w http.ResponseWriter, r *http.Request) {

	fmt.Println(r.Method)
	if r.Method == http.MethodPost {
		idx := parseId(r.PathValue("id"))

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		mu.Lock()
		defer mu.Unlock()

		todos[idx].ImageUrl = r.FormValue("imageUrl")
		todos[idx].Name = r.FormValue("description")

		if r.Header.Get("HX-Request") == "true" {
			if err := tmplTodo.ExecuteTemplate(w, "todo-item", TemplateTodo{
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

func main() {
	http.HandleFunc("/", todoListHandler)
	http.HandleFunc("/reserve/{id}", reserveTodoHandler)
	http.HandleFunc("/item/{id}", itemHandler)
	http.HandleFunc("/edit/{id}", editHandler)
	http.HandleFunc("/edit/{id}/done", editDoneHandler)
	http.ListenAndServe(":8080", nil)

}
