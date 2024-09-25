package main

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"sync"
)

type Wish struct {
	Description string
	Reserved    bool
	ImageUrl    string
}

type TemplateWish struct {
	Index int
	Wish  Wish
}

var (
	defaultImage = "https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fget.pxhere.com%2Fphoto%2Fplant-fruit-food-produce-banana-healthy-eat-single-fruits-diet-vitamins-flowering-plant-land-plant-banana-family-cooking-plantain-1386949.jpg&f=1&nofb=1&ipt=756f2c2f08e9e3d1179ece67b7cb35e273fb41c12923ddeaf5b46527e2c62c4b&ipo=images"
	wishlist     = []Wish{
		{"Eine Reise nach Neuseeland", false, defaultImage},
		{"Eine Maus, die mich lieb hat!", true, defaultImage},
		{"Ein liebes Glücksbärchen", false, defaultImage},
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

	data := make([]TemplateWish, len(wishlist))
	for i, t := range wishlist {
		data[i].Index = i
		data[i].Wish = t
	}

	if err := templateWishlist.ExecuteTemplate(w, "all", data); err != nil {
		fmt.Println(err)
	}

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

		if r.Header.Get("HX-Request") == "true" {
			if err := templateWishlist.ExecuteTemplate(w, "wish-item", struct {
				Index int
				Wish  Wish
			}{
				Index: idx,
				Wish:  wishlist[idx],
			}); err != nil {
				fmt.Println(err)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}

}

func itemHandler(w http.ResponseWriter, r *http.Request) {

	// Delete an item!
	if r.Method == http.MethodDelete {
		idx := parseId(r.PathValue("id"), false)

		// possibly a cancel on a newly created item. Lets just return nothing instead!
		if idx == -1 {
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

		if r.Header.Get("HX-Request") == "true" {
			if err := templateWishlist.ExecuteTemplate(w, "wish-item", struct {
				Index int
				Wish  Wish
			}{
				Index: idx,
				Wish:  wishlist[idx],
			}); err != nil {
				fmt.Println(err)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func editHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {
		idx := parseId(r.PathValue("id"), true)

		mu.Lock()
		defer mu.Unlock()

		if r.Header.Get("HX-Request") == "true" {
			if err := templateWishlist.ExecuteTemplate(w, "wish-edit", TemplateWish{
				Index: idx,
				Wish:  wishlist[idx],
			}); err != nil {
				fmt.Println(err)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func newItemHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {

		mu.Lock()
		defer mu.Unlock()

		if r.Header.Get("HX-Request") == "true" {
			if err := templateWishlist.ExecuteTemplate(w, "new-wish", TemplateWish{
				Index: -1, // An invalid index so that we generate a new item after the OK-button
				Wish:  Wish{"", false, ""},
			}); err != nil {
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
			wishlist = append(wishlist, Wish{"", false, ""})
			idx = len(wishlist) - 1
		}

		wishlist[idx].ImageUrl = r.FormValue("imageUrl")
		wishlist[idx].Description = r.FormValue("description")

		if r.Header.Get("HX-Request") == "true" {
			if err := templateWishlist.ExecuteTemplate(w, "wish-item", TemplateWish{
				Index: idx,
				Wish:  wishlist[idx],
			}); err != nil {
				fmt.Println(err)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
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
