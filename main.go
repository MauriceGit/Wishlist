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
	// Side can be: "start" or "end" and will determine if the button aligns to left or right (will be used as "justify-{{.Side}}")
	Side string
}

type TemplateWish struct {
	Index int
	Wish  Wish
}

type TemplateEditWish struct {
	Index   int
	Wish    Wish
	NewLink Button
}

type TemplateAll struct {
	Wishlist []TemplateWish
	NewWish  Button
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

	tmpTemplate := template.Must(template.ParseFiles("templates/wishlist.html"))

	data := TemplateAll{
		Wishlist: make([]TemplateWish, len(wishlist)),
		NewWish:  Button{"/new", "bg-blue-400", "bg-blue-500", "end"},
	}
	for i, t := range wishlist {
		data.Wishlist[i].Index = i
		data.Wishlist[i].Wish = t
	}

	if err := tmpTemplate.ExecuteTemplate(w, "all", data); err != nil {
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

func deleteHandler(w http.ResponseWriter, r *http.Request) {

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
}

func itemHandler(w http.ResponseWriter, r *http.Request) {

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
		if idx < 0 {
			return
		}

		mu.Lock()
		defer mu.Unlock()

		if r.Header.Get("HX-Request") == "true" {
			if err := templateWishlist.ExecuteTemplate(w, "wish-edit", TemplateEditWish{
				Index:   idx,
				Wish:    wishlist[idx],
				NewLink: Button{"/addlink", "bg-amber-300", "bg-amber-400", "start"},
			}); err != nil {
				fmt.Println(err)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func addLinkHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {
		mu.Lock()
		defer mu.Unlock()

		if r.Header.Get("HX-Request") == "true" {
			if err := templateWishlist.ExecuteTemplate(w, "add-link", struct {
				Link    string
				NewLink Button
			}{
				Link:    "",
				NewLink: Button{"/addlink", "bg-amber-300", "bg-amber-400", "start"},
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

		data := struct {
			EditWish TemplateEditWish
			NewWish  Button
		}{
			EditWish: TemplateEditWish{
				Index:   -1, // An invalid index so that we generate a new item after the OK-button
				Wish:    Wish{"", "", nil, "", false},
				NewLink: Button{"/addlink", "bg-amber-300", "bg-amber-400", "start"},
			},
			NewWish: Button{"/new", "bg-blue-400", "bg-blue-500", "end"},
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

		// filter empty links
		links := make([]string, 0)
		for _, l := range r.Form["link"] {
			if l != "" {
				links = append(links, l)
			}
		}

		wishlist[idx].Name = r.FormValue("name")
		wishlist[idx].Description = r.FormValue("description")
		wishlist[idx].Links = links
		wishlist[idx].ImageUrl = r.FormValue("imageUrl")

		writeTemplateWish(w, r, "wish-item", idx)
	}

}

func main() {
	http.HandleFunc("/", wishlistHandler)
	http.HandleFunc("/reserve/{id}", reserveWishHandler)
	http.HandleFunc("/new", newItemHandler)
	http.HandleFunc("/item/{id}", itemHandler)
	http.HandleFunc("/delete/{id}", deleteHandler)
	http.HandleFunc("/edit/{id}", editHandler)
	http.HandleFunc("/edit/{id}/done", editDoneHandler)
	http.HandleFunc("/addlink", addLinkHandler)
	http.ListenAndServe(":8080", nil)
}
