package main

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"sync"
)

type Wish struct {
	Name        string
	Description string
	Links       []string
	ImageUrl    string
	Reserved    bool
}

type Button struct {
	Link           string
	Color          string
	ColorHighlight string
}

type TemplateWish struct {
	Index int
	Wish  Wish
}

type TemplateAll struct {
	Wishlist []TemplateWish
	Button   Button
}

var (
	defaultImage = "https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fget.pxhere.com%2Fphoto%2Fplant-fruit-food-produce-banana-healthy-eat-single-fruits-diet-vitamins-flowering-plant-land-plant-banana-family-cooking-plantain-1386949.jpg&f=1&nofb=1&ipt=756f2c2f08e9e3d1179ece67b7cb35e273fb41c12923ddeaf5b46527e2c62c4b&ipo=images"
	wishlist     = []Wish{
		{"Neuseeland", "Eine Reise nach Neuseeland", []string{"http://link1.com"}, defaultImage, false},
		{"Liebe", "Eine Maus, die mich lieb hat!", []string{"http://link1.com", "https://link2.de/blubb"}, "", true},
		{"Bär", "Ein liebes Glücksbärchen", nil, defaultImage, false},
	}
	mu sync.Mutex

	templateWishlist = template.Must(template.ParseFiles("templates/wishlist.html"))
)

func parseId(id string, strict bool) int {
	idx, err := strconv.Atoi(id)
	if err != nil || strict && (idx < 0 || idx >= len(wishlist)) {
		fmt.Printf("Parsing the id '%v' results in err '%v' or an index that is out-of-bounds\n", id, err)
		return -2
	}
	return idx
}

// Handler for rendering the full list
func wishlistHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	data := TemplateAll{
		Wishlist: make([]TemplateWish, len(wishlist)),
		Button:   Button{"/new", "bg-lime-600", "bg-lime-700"},
	}
	for i, t := range wishlist {
		data.Wishlist[i].Index = i
		data.Wishlist[i].Wish = t
	}

	if err := templateWishlist.ExecuteTemplate(w, "all", data); err != nil {
		fmt.Println(err)
	}

}

func writeTemplateWish(w http.ResponseWriter, r *http.Request, template string, idx int) {
	if r.Header.Get("HX-Request") == "true" {
		if err := templateWishlist.ExecuteTemplate(w, template, TemplateWish{
			Index: idx,
			Wish:  wishlist[idx],
		}); err != nil {
			fmt.Println(err)
		}
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Handler to toggle todo item
func reserveWishHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		idx := parseId(r.PathValue("id"), false)

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		mu.Lock()
		defer mu.Unlock()

		reserve := r.FormValue("reserve") == "true"
		wishlist[idx].Reserved = reserve

		writeTemplateWish(w, r, "wish-item", idx)
	}

}

func itemHandler(w http.ResponseWriter, r *http.Request) {

	// Delete an item!
	if r.Method == http.MethodDelete {
		idx := parseId(r.PathValue("id"), false)

		// possibly a cancel on a newly created item. Lets just return nothing instead!
		if idx < 0 {
			return
		}

		mu.Lock()
		defer mu.Unlock()

		wishlist = append(wishlist[:idx], wishlist[idx+1:]...)

		// Return nothing. That should just remove the currently edited item!
	}

	if r.Method == http.MethodGet {
		idx := parseId(r.PathValue("id"), false)

		// possibly a cancel on a newly created item. Lets just return nothing instead!
		if idx == -1 {
			return
		}

		mu.Lock()
		defer mu.Unlock()

		writeTemplateWish(w, r, "wish-item", idx)
	}
}

func editHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {
		idx := parseId(r.PathValue("id"), true)

		mu.Lock()
		defer mu.Unlock()

		writeTemplateWish(w, r, "wish-edit", idx)
	}
}

func newItemHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {

		mu.Lock()
		defer mu.Unlock()

		data := struct {
			Index  int
			Wish   Wish
			Button Button
		}{
			Index:  -1, // An invalid index so that we generate a new item after the OK-button
			Wish:   Wish{"", "", nil, "", false},
			Button: Button{"/new", "bg-lime-600", "bg-lime-700"},
		}

		if r.Header.Get("HX-Request") == "true" {
			if err := templateWishlist.ExecuteTemplate(w, "new-wish", data); err != nil {
				fmt.Println(err)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func editDoneHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodPost {
		idx := parseId(r.PathValue("id"), false)

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		mu.Lock()
		defer mu.Unlock()

		// A new item was added!
		if idx == -1 {
			wishlist = append(wishlist, Wish{"", "", nil, "", false})
			idx = len(wishlist) - 1
		}

		wishlist[idx].Name = r.FormValue("name")
		wishlist[idx].Description = r.FormValue("description")
		wishlist[idx].Links = []string{r.FormValue("link")}
		wishlist[idx].ImageUrl = r.FormValue("imageUrl")

		writeTemplateWish(w, r, "wish-item", idx)
	}

}

func main() {
	http.HandleFunc("/", wishlistHandler)
	http.HandleFunc("/reserve/{id}", reserveWishHandler)
	http.HandleFunc("/new", newItemHandler)
	http.HandleFunc("/item/{id}", itemHandler)
	http.HandleFunc("/edit/{id}", editHandler)
	http.HandleFunc("/edit/{id}/done", editDoneHandler)
	http.ListenAndServe(":8080", nil)
}
