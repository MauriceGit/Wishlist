package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"sync"
	"time"
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
	Title         string
	Wishlist      []TemplateWish
	NewWish       Button
	Authenticated bool
	Username      string
}

type session struct {
	username string
	expire   time.Time
}

type Wishlist struct {
	Title  string
	Wishes []Wish
}

type userdata struct {
	passwordHash []byte
	Wishlists    []Wishlist
}

var (
	defaultImage = "https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fget.pxhere.com%2Fphoto%2Fplant-fruit-food-produce-banana-healthy-eat-single-fruits-diet-vitamins-flowering-plant-land-plant-banana-family-cooking-plantain-1386949.jpg&f=1&nofb=1&ipt=756f2c2f08e9e3d1179ece67b7cb35e273fb41c12923ddeaf5b46527e2c62c4b&ipo=images"

	/*
		wishlist     = []Wish{
			{"Neuseeland", "Eine Reise nach Neuseeland", []string{"http://link1.com"}, defaultImage, false},
			{"Liebe", "Eine Maus, die mich lieb hat!", []string{"http://link1.com", "https://link2.de/blubb"}, "", true},
			{"Bär", "Ein liebes Glücksbärchen", nil, defaultImage, false},
		}
	*/
	mu sync.Mutex

	users    = map[string]userdata{}
	sessions = map[string]session{}

	templateWishlist = template.Must(template.ParseFiles("templates/wishlist.html"))
)

func (s *session) isExpired() bool {
	return s.expire.Before(time.Now())
}

func parseId(id string) int {
	idx, err := strconv.Atoi(id)
	if err != nil {
		fmt.Printf("Parsing the id '%v' results in err '%v'\n", id, err)
		return -2
	}
	return idx
}

// checkAuthentication checks, if the user is currently logged in and returns the username.
func checkAuthentication(r *http.Request) (string, bool, int) {
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			return "", false, http.StatusUnauthorized
		}
		return "", false, http.StatusBadRequest
	}
	sessionToken := c.Value

	fmt.Printf("Check session with token: '%v'\n", sessionToken)

	session, ok := sessions[sessionToken]
	if !ok {
		fmt.Println("Session not ok!")
		return "", false, http.StatusUnauthorized
	}

	if session.isExpired() {
		fmt.Println("Session expired???")
		delete(sessions, sessionToken)
		return "", false, http.StatusUnauthorized
	}
	return session.username, true, 0
}

// handleUserAuthentication will check, if the user is authenticated and return true.
// Otherwise it will redirect to / and return false
func handleUserAuthentication(w http.ResponseWriter, r *http.Request) (string, bool) {
	user, ok, statusCode := checkAuthentication(r)
	if !ok {
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(statusCode)
	}
	return user, ok
}

// landingPageHandler handles the landing page. If the user is not authenticated, it will show the login screen.
// otherwise it will show the users wishlists.
func allHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	user, ok, _ := checkAuthentication(r)

	tmpTemplate := template.Must(template.ParseFiles("templates/wishlist.html"))

	data := struct {
		Wishlists     []Wishlist
		Authenticated bool
		Username      string
	}{
		Wishlists:     nil,
		Authenticated: ok,
		Username:      user,
	}

	if ok {
		data.Wishlists = users[user].Wishlists
	}

	if err := tmpTemplate.ExecuteTemplate(w, "all", data); err != nil {
		fmt.Println(err)
	}
}

// landingPageHandler handles the landing page. If the user is not authenticated, it will show the login screen.
// otherwise it will show the users wishlists.
func landingpageHandler(w http.ResponseWriter, r *http.Request) {

	if err := templateWishlist.ExecuteTemplate(w, "landing-page", nil); err != nil {
		fmt.Println(err)
	}
}

func overviewHandler(w http.ResponseWriter, r *http.Request) {
	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {
		mu.Lock()
		defer mu.Unlock()

		if err := templateWishlist.ExecuteTemplate(w, "overview", users[user]); err != nil {
			fmt.Println(err)
		}
	}
}

func wishlistHandler(w http.ResponseWriter, r *http.Request) {
	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {

		idx := parseId(r.PathValue("id"))

		mu.Lock()
		defer mu.Unlock()

		data := TemplateAll{
			Title:         users[user].Wishlists[idx].Title,
			Wishlist:      make([]TemplateWish, len(users[user].Wishlists[idx].Wishes)),
			NewWish:       Button{"/new", "bg-blue-400", "bg-blue-500", "end"},
			Authenticated: ok,
			Username:      user,
		}

		for i, t := range users[user].Wishlists[idx].Wishes {
			data.Wishlist[i].Index = i
			data.Wishlist[i].Wish = t
		}

		if err := templateWishlist.ExecuteTemplate(w, "wishlist", data); err != nil {
			fmt.Println(err)
		}
	}
}

// wishlistHandler handles the landing page. If the user is not authenticated, it will show the login screen.
// otherwise it will show the users wishlist.
func wishlistHandler_____(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	user, ok, _ := checkAuthentication(r)
	fmt.Printf("Authenticate user '%v': %v\n", user, ok)

	tmpTemplate := template.Must(template.ParseFiles("templates/wishlist.html"))

	data := TemplateAll{
		Wishlist:      nil,
		NewWish:       Button{"/new", "bg-blue-400", "bg-blue-500", "end"},
		Authenticated: ok,
		Username:      user,
	}
	if ok {
		wishlist := users[user].Wishlists[0]
		data.Wishlist = make([]TemplateWish, len(wishlist.Wishes))
		for i, t := range wishlist.Wishes {
			data.Wishlist[i].Index = i
			data.Wishlist[i].Wish = t
		}
	}

	if err := tmpTemplate.ExecuteTemplate(w, "all", data); err != nil {
		fmt.Println(err)
	}
}

// https://stackoverflow.com/questions/15130321/is-there-a-method-to-generate-a-uuid-with-go-language
func newUUID() (error, string) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error: ", err)
		return err, ""
	}
	return nil, fmt.Sprintf("%X", b)
}

func hashPassword(user, password string) []byte {
	h := sha256.New()
	h.Write([]byte(password))
	h.Write([]byte(user))
	return h.Sum(nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	tmpTemplate := template.Must(template.ParseFiles("templates/wishlist.html"))

	if r.Method == http.MethodPost {
		mu.Lock()
		defer mu.Unlock()

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			if err := tmpTemplate.ExecuteTemplate(w, "login-error", nil); err != nil {
				fmt.Println(err)
			}
			return
		}

		fmt.Println(r.Form)

		user := r.FormValue("email")
		password := r.FormValue("password")
		pHash := hashPassword(user, password)
		fmt.Printf("%v\n", pHash)

		userData, ok := users[user]
		if !ok {
			fmt.Printf("User '%v' does not exist.\n", user)
			w.WriteHeader(http.StatusOK)
			if err := tmpTemplate.ExecuteTemplate(w, "login-error", nil); err != nil {
				fmt.Println(err)
			}
			return
		}

		if !bytes.Equal(pHash, userData.passwordHash) {
			//if pHash != userData.passwordHash {
			fmt.Printf("User '%v' exists, but wrong password.\n", user)
			w.WriteHeader(http.StatusUnauthorized)
			if err := tmpTemplate.ExecuteTemplate(w, "login-error", nil); err != nil {
				fmt.Println(err)
			}
			return
		}

		err, sessionToken := newUUID()
		if err != nil {
			fmt.Printf("Error when generating a new uuid: %v\n", err)
			w.WriteHeader(http.StatusUnauthorized)
			if err := tmpTemplate.ExecuteTemplate(w, "login-error", nil); err != nil {
				fmt.Println(err)
			}
			return
		}
		sessionExpire := time.Now().Add(10 * time.Minute)

		sessions[sessionToken] = session{
			username: user,
			expire:   sessionExpire,
		}

		fmt.Printf("New session for user '%v' and uuid: '%v'\n", user, sessionToken)

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Expires:  sessionExpire,
			Path:     "/",                   // Ensures the cookie is available throughout the site
			SameSite: http.SameSiteNoneMode, // Use Lax, or change to Strict or None as per your needs
			Secure:   false,                 // Must be true if SameSite=None (requires HTTPS)
			HttpOnly: true,                  // Prevents JavaScript from accessing the cookie
		})

		// User authenticated and everything is OK
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
		//http.Redirect(w, r, "/overview", http.StatusSeeOther)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok {

		// handleUserAuthentication makes sure, that the cookie and session_token exist!
		c, _ := r.Cookie("session_token")
		sessionToken := c.Value

		fmt.Printf("Successfully logged out user '%v'\n", user)

		// remove user session!
		delete(sessions, sessionToken)

		// We need to let the client know that the cookie is expired
		// In the response, we set the session token to an empty
		// value and set its expiry as the current time
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    "",
			Expires:  time.Now(),
			Path:     "/",                   // Ensures the cookie is available throughout the site
			SameSite: http.SameSiteNoneMode, // Use Lax, or change to Strict or None as per your needs
			Secure:   false,                 // Must be true if SameSite=None (requires HTTPS)
			HttpOnly: true,                  // Prevents JavaScript from accessing the cookie
		})

		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	}
}

func writeTemplateWish(w http.ResponseWriter, r *http.Request, template string, idx int, wish Wish) {

	if r.Header.Get("HX-Request") == "true" {
		if err := templateWishlist.ExecuteTemplate(w, template, TemplateWish{
			Index: idx,
			Wish:  wish,
		}); err != nil {
			fmt.Println(err)
		}
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Handler to toggle todo item
func reserveWishHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {

		idx := parseId(r.PathValue("id"))

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		mu.Lock()
		defer mu.Unlock()

		reserve := r.FormValue("reserve") == "true"
		users[user].Wishlists[0].Wishes[idx].Reserved = reserve

		writeTemplateWish(w, r, "wish-item", idx, users[user].Wishlists[0].Wishes[idx])
	}
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {

	// Delete an item!
	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodDelete {
		idx := parseId(r.PathValue("id"))

		// possibly a cancel on a newly created item. Lets just return nothing instead!
		if idx < 0 {
			return
		}

		mu.Lock()
		defer mu.Unlock()

		wishlist := users[user].Wishlists[0].Wishes
		users[user].Wishlists[0].Wishes = append(wishlist[:idx], wishlist[idx+1:]...)

		// Return nothing. That should just remove the currently edited item!
	}
}

func itemHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {
		idx := parseId(r.PathValue("id"))

		// possibly a cancel on a newly created item. Lets just return nothing instead!
		if idx == -1 {
			return
		}

		mu.Lock()
		defer mu.Unlock()

		wish := users[user].Wishlists[0].Wishes[idx]
		writeTemplateWish(w, r, "wish-item", idx, wish)
	}
}

func editHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {
		idx := parseId(r.PathValue("id"))
		if idx < 0 {
			return
		}

		mu.Lock()
		defer mu.Unlock()

		if r.Header.Get("HX-Request") == "true" {
			if err := templateWishlist.ExecuteTemplate(w, "wish-edit", TemplateEditWish{
				Index:   idx,
				Wish:    users[user].Wishlists[0].Wishes[idx],
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

	if _, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {
		mu.Lock()
		defer mu.Unlock()

		if r.Header.Get("HX-Request") == "true" {
			if err := templateWishlist.ExecuteTemplate(w, "link", ""); err != nil {
				fmt.Println(err)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		mu.Lock()
		defer mu.Unlock()

		if r.Header.Get("HX-Request") == "true" {
			if err := templateWishlist.ExecuteTemplate(w, "login", nil); err != nil {
				fmt.Println(err)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func newItemHandler(w http.ResponseWriter, r *http.Request) {

	if _, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {

		data := TemplateEditWish{
			Index:   -1, // An invalid index so that we generate a new item after the OK-button
			Wish:    Wish{"", "", nil, "", false},
			NewLink: Button{"/addlink", "bg-amber-300", "bg-amber-400", "start"},
		}

		if r.Header.Get("HX-Request") == "true" {
			if err := templateWishlist.ExecuteTemplate(w, "wish-edit", data); err != nil {
				fmt.Println(err)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func editDoneHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodPost {
		idx := parseId(r.PathValue("id"))

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		mu.Lock()
		defer mu.Unlock()

		// A new item was added!
		if idx == -1 {
			users[user].Wishlists[0].Wishes = append(users[user].Wishlists[0].Wishes, Wish{"", "", nil, "", false})
			idx = len(users[user].Wishlists[0].Wishes) - 1
		}

		// filter empty links
		links := make([]string, 0)
		for _, l := range r.Form["link"] {
			if l != "" {
				links = append(links, l)
			}
		}

		users[user].Wishlists[0].Wishes[idx].Name = r.FormValue("name")
		users[user].Wishlists[0].Wishes[idx].Description = r.FormValue("description")
		users[user].Wishlists[0].Wishes[idx].Links = links
		users[user].Wishlists[0].Wishes[idx].ImageUrl = r.FormValue("imageUrl")

		writeTemplateWish(w, r, "wish-item", idx, users[user].Wishlists[0].Wishes[idx])
	}
}

func main() {

	mWishlist := Wishlist{
		Title: "Wunschliste",
		Wishes: []Wish{
			{"Neuseeland", "Eine Reise nach Neuseeland", []string{"http://link1.com"}, defaultImage, false},
			{"Liebe", "Eine Maus, die mich lieb hat!", []string{"http://link1.com", "https://link2.de/blubb"}, "", true},
			{"Bär", "Ein liebes Glücksbärchen", nil, defaultImage, false},
		},
	}
	gold := "https://www.muenzeoesterreich.at/var/em_plain_site/storage/images/_aliases/product_full/media/bilder/produktbilder/1.anlegen/handelsgold_mtt/1fach-dukaten-av/9572-4-ger-DE/1fach-dukaten-av.png"
	kinderwagen := "https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fi.otto.de%2Fi%2Fotto%2F16455872-f2bb-5a61-bfb2-261f5713a79a%3Fh%26%2361%3B520%26amp%3Bw%2661%3B551%26amp%3Bsm%2661%3Bclamp&f=1&nofb=1&ipt=492a936d362bfd9dfa8095c11c15251238c529f986d731b49d66a8a3f162df81&ipo=images"
	nWishlist := Wishlist{
		Title: "Nadines Wunschliste",
		Wishes: []Wish{
			{"Ganz viel Gold und Reichtum", "Oder so. Ich muss da nochmal nachfragen :)", []string{"gold.de"}, gold, false},
			{"Ein Spaziergehpapabärchen", "Am liebsten jeden Morgen und nachmittags nochmal!", nil, kinderwagen, true},
			{"Ein frisch gesaugtes Bad und Schlafzimmer", "Das hätte ich gerne zu Weihnachten", nil, defaultImage, false},
		},
	}
	users["Maurice"] = userdata{
		passwordHash: hashPassword("Maurice", "passwort"),
		Wishlists:    []Wishlist{mWishlist},
	}
	users["Nadine"] = userdata{
		passwordHash: hashPassword("Nadine", "passwort"),
		Wishlists:    []Wishlist{nWishlist},
	}

	http.HandleFunc("/", allHandler)
	http.HandleFunc("/landingpage", landingpageHandler)
	http.HandleFunc("/overview", overviewHandler)
	http.HandleFunc("/wishlist/{id}", wishlistHandler)

	http.HandleFunc("/reserve/{id}", reserveWishHandler)
	http.HandleFunc("/new", newItemHandler)
	http.HandleFunc("/item/{id}", itemHandler)
	http.HandleFunc("/delete/{id}", deleteHandler)
	http.HandleFunc("/edit/{id}", editHandler)
	http.HandleFunc("/edit/{id}/done", editDoneHandler)
	http.HandleFunc("/addlink", addLinkHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/loginpage", loginPageHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.ListenAndServe(":8080", nil)
}
