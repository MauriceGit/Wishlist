package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"sync"
	"time"
	"wishlist/sqlc"

	_ "github.com/mattn/go-sqlite3"
)

// ======================== Used to communicate with html/template

type Button struct {
	Link           string
	Color          string
	ColorHighlight string
	// Side can be: "start" or "end" and will determine if the button aligns to left or right (will be used as "justify-{{.Side}}")
	Side string
}

type TemplateWish struct {
	Index     int
	Wish      Wish
	IsCreator bool
	Creator   string
}

// ======================== Session Data

type session struct {
	username string
	expire   time.Time
}

// ======================== Internal Wishlist data structures

type Wish struct {
	Name        string
	Description string
	Links       []string
	ImageUrl    string
	Reserved    bool
}

type Wishlist struct {
	Title  string
	UUID   string
	Wishes []Wish
}

type userdata struct {
	passwordHash []byte
	Wishlists    []Wishlist
}

type shortcut struct {
	user          string
	wishlistIndex int
}

var (
	defaultImage = "https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fget.pxhere.com%2Fphoto%2Fplant-fruit-food-produce-banana-healthy-eat-single-fruits-diet-vitamins-flowering-plant-land-plant-banana-family-cooking-plantain-1386949.jpg&f=1&nofb=1&ipt=756f2c2f08e9e3d1179ece67b7cb35e273fb41c12923ddeaf5b46527e2c62c4b&ipo=images"

	mu sync.Mutex

	users    = map[string]userdata{}
	sessions = map[string]session{}
	// Shortcuts are references from wishlist uuids to the user/index of the wishlist.
	// This avoids iterating all users/wishlists when searching for a specific one.
	shortcuts = map[string]shortcut{}

	funcMap = template.FuncMap{"newButton": newButton}

	tmplFullLandingpage = template.Must(template.ParseFiles("templates/main.html", "templates/landing-page.html"))
	tmplFullOverview    = template.Must(template.New("overview").Funcs(funcMap).ParseFiles("templates/main.html", "templates/overview.html", "templates/other.html"))
	tmplFullWishlist    = template.Must(template.New("testall").Funcs(funcMap).ParseFiles(
		"templates/main.html", "templates/wishlist.html", "templates/other.html",
	))
	tmplOther = template.Must(template.New("testall").Funcs(funcMap).ParseFiles(
		"templates/other.html",
	))

	//go:embed schema.sql
	ddl       string
	ctx       = context.Background()
	db        *sql.DB
	dbQueries *sqlc.Queries
)

func (s *session) isExpired() bool {
	return s.expire.Before(time.Now())
}

func newButton(link, color, colorHighlight, side string) Button {
	return Button{link, color, colorHighlight, side}
}

// This function will be used in the html/template to provide both wish and current index to the sub-template!
func (wish Wish) BundleIndex(index int, isCreator bool) TemplateWish {
	return TemplateWish{index, wish, isCreator, ""}
}

func parseIndex(id string) int {
	idx, err := strconv.Atoi(id)
	if err != nil {
		fmt.Printf("Parsing the id '%v' results in err '%v'\n", id, err)
		return -2
	}
	return idx
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

	user, authenticated, _ := checkAuthentication(r)

	data := struct {
		Wishlists     []Wishlist
		Authenticated bool
		Username      string
	}{
		Wishlists:     nil,
		Authenticated: authenticated,
		Username:      user,
	}

	uuid := r.PathValue("uuid")
	// We do not check the user or run authentication here because this page can be opened without being logged in.
	uuidOK := checkWishlistUUID(uuid)

	// Check the DB if there is a valid wishlist
	if !uuidOK && uuid != "" {
		dbwl, err := dbQueries.GetWishlist(ctx, uuid)
		if err != nil {
			fmt.Printf("Wishlist with uuid '%v' not found in DB: %v\n", uuid, err)
		} else {
			// TODO: Same/Similar code as in the login handler. Put this in a function!
			userData, err := loadUserDataFromDB(dbwl.UserName)
			if err == nil {
				users[dbwl.UserName] = userData
				for wlIndex, wl := range users[dbwl.UserName].Wishlists {
					shortcuts[wl.UUID] = shortcut{dbwl.UserName, wlIndex}
				}
				uuidOK = true
			}
		}
	}

	// If we only show one wishlist, it doesn't matter if the user is authenticated or not!
	if uuidOK {
		sc := shortcuts[uuid]
		wishlist := users[sc.user].Wishlists[sc.wishlistIndex]

		data := struct {
			Title         string
			UUID          string
			Wishes        []Wish
			Authenticated bool
			Username      string
			IsCreator     bool
			Creator       string
		}{
			Title:         wishlist.Title,
			UUID:          wishlist.UUID,
			Wishes:        wishlist.Wishes,
			Authenticated: authenticated,
			Username:      user,
			IsCreator:     user == sc.user,
			Creator:       sc.user,
		}

		if err := tmplFullWishlist.ExecuteTemplate(w, "all", data); err != nil {
			fmt.Println(err)
		}
		return
	}

	// Authenticated users get the wishlist overview
	if authenticated {
		data.Wishlists = users[user].Wishlists
		if err := tmplFullOverview.ExecuteTemplate(w, "all", data); err != nil {
			fmt.Println(err)
		}
		return
	}

	// For all other cases, just show the landing page!
	if err := tmplFullLandingpage.ExecuteTemplate(w, "all", data); err != nil {
		fmt.Println(err)
	}
}

// landingPageHandler handles the landing page. If the user is not authenticated, it will show the login screen.
// otherwise it will show the users wishlists.
func landingpageHandler(w http.ResponseWriter, r *http.Request) {
	if err := tmplFullLandingpage.ExecuteTemplate(w, "content", nil); err != nil {
		fmt.Println(err)
	}
}

func overviewHandler(w http.ResponseWriter, r *http.Request) {
	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {
		if err := tmplFullOverview.ExecuteTemplate(w, "content", users[user]); err != nil {
			fmt.Println(err)
		}
	}
}

// checkWishlistUUID checks if the uuid corresponds to a valid user and there exists a wishlist with the identical uuid!
func checkWishlistUUID(uuid string) bool {
	if sc, ok := shortcuts[uuid]; ok {
		if user, ok := users[sc.user]; ok {
			return sc.wishlistIndex < len(user.Wishlists) && user.Wishlists[sc.wishlistIndex].UUID == uuid
		}
	}
	return false
}

func wishlistHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {

		uuid := r.PathValue("uuid")
		if !checkWishlistUUID(uuid) || shortcuts[uuid].user != user {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}

		sc := shortcuts[uuid]
		wishlist := users[sc.user].Wishlists[sc.wishlistIndex]

		data := struct {
			Title     string
			UUID      string
			Wishes    []Wish
			IsCreator bool
			Creator   string
		}{
			Title:     wishlist.Title,
			UUID:      wishlist.UUID,
			Wishes:    wishlist.Wishes,
			IsCreator: user == sc.user,
			Creator:   sc.user,
		}

		if err := tmplFullWishlist.ExecuteTemplate(w, "content", data); err != nil {
			fmt.Println(err)
		}
	}
}

func newwishlistHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {

		var wishlist Wishlist
		wlIndex := len(users[user].Wishlists)
		wishlist.Title = fmt.Sprintf("Wishlist %v", wlIndex+1)
		err, uuid := newUUID()
		if err != nil {
			fmt.Printf("Error creating new UUID: %v\n", err)
			return
		}
		wishlist.UUID = uuid

		tmpUser := users[user]
		tmpUser.Wishlists = append(users[user].Wishlists, wishlist)
		users[user] = tmpUser
		shortcuts[uuid] = shortcut{user, wlIndex}

		if err := dbQueries.CreateWishlist(ctx, sqlc.CreateWishlistParams{uuid, user, wishlist.Title}); err != nil {
			fmt.Printf("Creating DB wishlist failed: %v\n", err)
		}

		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	}
}

func editwishlistHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {
		uuid := r.PathValue("uuid")
		if !checkWishlistUUID(uuid) || shortcuts[uuid].user != user {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}

		if r.Header.Get("HX-Request") == "true" {
			sc := shortcuts[uuid]
			wishlist := users[sc.user].Wishlists[sc.wishlistIndex]
			if err := tmplFullWishlist.ExecuteTemplate(w, "wishlist-edit", wishlist); err != nil {
				fmt.Println(err)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func renderWishlistTitle(w http.ResponseWriter, wishlist Wishlist, isCreator bool) {
	if err := tmplFullWishlist.ExecuteTemplate(w, "wishlist-title", struct {
		Title     string
		UUID      string
		IsCreator bool
	}{
		Title:     wishlist.Title,
		UUID:      wishlist.UUID,
		IsCreator: isCreator,
	}); err != nil {
		fmt.Println(err)
	}
}

func wishlisttitleHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {
		uuid := r.PathValue("uuid")
		if !checkWishlistUUID(uuid) || shortcuts[uuid].user != user {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}

		if r.Header.Get("HX-Request") == "true" {
			sc := shortcuts[uuid]
			wishlist := users[sc.user].Wishlists[sc.wishlistIndex]

			renderWishlistTitle(w, wishlist, user == sc.user)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func editwishlistDoneHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodPost {
		uuid := r.PathValue("uuid")
		if !checkWishlistUUID(uuid) || shortcuts[uuid].user != user {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		if r.Header.Get("HX-Request") == "true" {
			sc := shortcuts[uuid]

			tmpUserdata := users[sc.user]
			tmpUserdata.Wishlists[sc.wishlistIndex].Title = r.FormValue("name")
			users[sc.user] = tmpUserdata

			if err := dbQueries.UpdateWishlist(ctx, sqlc.UpdateWishlistParams{r.FormValue("name"), uuid}); err != nil {
				fmt.Printf("Wishlist title update for db failed: %v\n", err)
			}

			renderWishlistTitle(w, users[sc.user].Wishlists[sc.wishlistIndex], user == sc.user)
			return
		}
		http.Redirect(w, r, "/wishlisttitle/"+uuid, http.StatusOK)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var err error
	if r.Method == http.MethodPost {
		mu.Lock()
		defer mu.Unlock()

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			if err := tmplOther.ExecuteTemplate(w, "login-error", nil); err != nil {
				fmt.Println(err)
			}
			return
		}

		user := r.FormValue("email")
		password := r.FormValue("password")
		pHash := hashPassword(user, password)

		// First check, if the user is already loaded from db
		userData, ok := users[user]
		if !ok {

			userData, err = loadUserDataFromDB(user)
			if err != nil {
				fmt.Println(err)
				w.WriteHeader(http.StatusOK)
				if err := tmplOther.ExecuteTemplate(w, "login-error", nil); err != nil {
					fmt.Println(err)
				}
				return
			}
			users[user] = userData
			for wlIndex, wl := range users[user].Wishlists {
				shortcuts[wl.UUID] = shortcut{user, wlIndex}
			}
		}

		if !bytes.Equal(pHash, userData.passwordHash) {
			fmt.Printf("User '%v' exists, but wrong password.\n", user)
			w.WriteHeader(http.StatusUnauthorized)
			if err := tmplOther.ExecuteTemplate(w, "login-error", nil); err != nil {
				fmt.Println(err)
			}
			return
		}

		err, sessionToken := newUUID()
		if err != nil {
			fmt.Printf("Error when generating a new uuid: %v\n", err)
			w.WriteHeader(http.StatusUnauthorized)
			if err := tmplOther.ExecuteTemplate(w, "login-error", nil); err != nil {
				fmt.Println(err)
			}
			return
		}
		sessionExpire := time.Now().Add(10 * time.Minute)

		sessions[sessionToken] = session{
			username: user,
			expire:   sessionExpire,
		}

		fmt.Printf("New session for user '%v'\n", user)

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Expires:  sessionExpire,
			Path:     "/",                  // Ensures the cookie is available throughout the site
			SameSite: http.SameSiteLaxMode, // Use Lax, or change to Strict or None as per your needs
			Secure:   false,                // Must be true if SameSite=None (requires HTTPS)
			HttpOnly: true,                 // Prevents JavaScript from accessing the cookie
		})

		// User authenticated and everything is OK
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
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

		// remove userdata from memory. Must be reloaded from db the next time this user logs in
		delete(users, user)

		// We need to let the client know that the cookie is expired
		// In the response, we set the session token to an empty
		// value and set its expiry as the current time
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    "",
			Expires:  time.Now(),
			Path:     "/",                  // Ensures the cookie is available throughout the site
			SameSite: http.SameSiteLaxMode, // Use Lax, or change to Strict or None as per your needs
			Secure:   false,                // Must be true if SameSite=None (requires HTTPS)
			HttpOnly: true,                 // Prevents JavaScript from accessing the cookie
		})

		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	}
}

func writeTemplateWish(w http.ResponseWriter, r *http.Request, template string, idx int, wish Wish, isCreator bool, creator string) {

	if r.Header.Get("HX-Request") == "true" {
		if err := tmplOther.ExecuteTemplate(w, template, TemplateWish{
			Index:     idx,
			Wish:      wish,
			IsCreator: isCreator,
			Creator:   creator,
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

		user, _, _ := checkAuthentication(r)

		idx := parseIndex(r.PathValue("idx"))

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		uuid := r.FormValue("wishlist-uuid")
		// Everyone (even not logged in) can reserve wishes. So no need to check against the user!
		if !checkWishlistUUID(uuid) {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}

		wlUser := shortcuts[uuid].user
		dbReserve := int64(0)
		reserveStr := "Unreserve"
		reserve := r.FormValue("reserve") == "true"
		if reserve {
			dbReserve = 1
			reserveStr = "Reserve"
		}
		fmt.Printf("%v wish %v for user '%v' and wishlist with uuid: %v by user '%v'\n", reserveStr, idx, wlUser, uuid, user)

		mu.Lock()
		defer mu.Unlock()

		wlIndex := shortcuts[uuid].wishlistIndex
		users[wlUser].Wishlists[wlIndex].Wishes[idx].Reserved = reserve

		if err := dbQueries.SetWishReserve(ctx, sqlc.SetWishReserveParams{dbReserve, uuid, int64(idx)}); err != nil {
			fmt.Printf("Wish reserve db write failed: %v\n", err)
		}

		writeTemplateWish(w, r, "wish-item", idx, users[wlUser].Wishlists[wlIndex].Wishes[idx], user == shortcuts[uuid].user, shortcuts[uuid].user)
	}
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {

	// Delete an item!
	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodPut {
		idx := parseIndex(r.PathValue("idx"))

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		uuid := r.FormValue("wishlist-uuid")
		if !checkWishlistUUID(uuid) || shortcuts[uuid].user != user {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}

		wlIndex := shortcuts[uuid].wishlistIndex
		// possibly a cancel on a newly created item. Lets just return nothing instead!
		if idx < 0 || idx >= len(users[user].Wishlists[wlIndex].Wishes) {
			return
		}

		fmt.Printf("Delete wish %v for user '%v' and wishlist with uuid: %v\n", idx, user, uuid)

		mu.Lock()
		defer mu.Unlock()

		wishlist := users[user].Wishlists[wlIndex].Wishes
		users[user].Wishlists[wlIndex].Wishes = append(wishlist[:idx], wishlist[idx+1:]...)

		if err := dbQueries.DeleteWish(ctx, sqlc.DeleteWishParams{uuid, int64(idx)}); err != nil {
			fmt.Printf("Delete wish DB write failed: %v\n", err)
		}

		// Return nothing. That should just remove the currently edited item!
	}
}

func itemHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {
		idx := parseIndex(r.PathValue("idx"))

		// possibly a cancel on a newly created item. Lets just return nothing instead!
		if idx == -1 {
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		uuid := r.FormValue("wishlist-uuid")
		if !checkWishlistUUID(uuid) || shortcuts[uuid].user != user {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}
		fmt.Printf("Show item %v for user '%v' and wishlist with uuid: %v\n", idx, user, uuid)

		mu.Lock()
		defer mu.Unlock()
		wlIndex := shortcuts[uuid].wishlistIndex
		wish := users[user].Wishlists[wlIndex].Wishes[idx]
		writeTemplateWish(w, r, "wish-item", idx, wish, user == shortcuts[uuid].user, shortcuts[uuid].user)
	}
}

func editHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {
		idx := parseIndex(r.PathValue("idx"))
		if idx < 0 {
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		uuid := r.FormValue("wishlist-uuid")
		if !checkWishlistUUID(uuid) || shortcuts[uuid].user != user {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}
		fmt.Printf("Show the edit of item %v for user '%v' and wishlist with uuid: %v\n", idx, user, uuid)

		if r.Header.Get("HX-Request") == "true" {
			wlIndex := shortcuts[uuid].wishlistIndex
			if err := tmplOther.ExecuteTemplate(w, "wish-edit", TemplateWish{
				Index: idx,
				Wish:  users[user].Wishlists[wlIndex].Wishes[idx],
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

		if r.Header.Get("HX-Request") == "true" {
			if err := tmplOther.ExecuteTemplate(w, "link", ""); err != nil {
				fmt.Println(err)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {

		if r.Header.Get("HX-Request") == "true" {
			if err := tmplOther.ExecuteTemplate(w, "login", nil); err != nil {
				fmt.Println(err)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func newItemHandler(w http.ResponseWriter, r *http.Request) {

	if _, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {

		data := TemplateWish{
			Index: -1, // An invalid index so that we generate a new item after the OK-button
			Wish:  Wish{"", "", nil, "", false},
		}

		if r.Header.Get("HX-Request") == "true" {
			if err := tmplOther.ExecuteTemplate(w, "wish-edit", data); err != nil {
				fmt.Println(err)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func editDoneHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodPost {
		idx := parseIndex(r.PathValue("idx"))

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		uuid := r.FormValue("wishlist-uuid")
		if !checkWishlistUUID(uuid) || shortcuts[uuid].user != user {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}
		fmt.Printf("Editing Done for item %v for user '%v' and wishlist with uuid: %v\n", idx, user, uuid)

		mu.Lock()
		defer mu.Unlock()

		isNewWish := false
		wlIndex := shortcuts[uuid].wishlistIndex
		// A new item was added!
		if idx == -1 {
			users[user].Wishlists[wlIndex].Wishes = append(users[user].Wishlists[wlIndex].Wishes, Wish{"", "", nil, "", false})
			idx = len(users[user].Wishlists[wlIndex].Wishes) - 1

			isNewWish = true

		}

		// filter empty links
		links := make([]string, 0)
		for _, l := range r.Form["link"] {
			if l != "" {
				links = append(links, l)
			}
		}

		users[user].Wishlists[wlIndex].Wishes[idx] = Wish{
			Name:        r.FormValue("name"),
			Description: r.FormValue("description"),
			Links:       links,
			ImageUrl:    r.FormValue("imageUrl"),
			Reserved:    users[user].Wishlists[wlIndex].Wishes[idx].Reserved,
		}
		wi := users[user].Wishlists[wlIndex].Wishes[idx]
		dbReserved := int64(0)
		if wi.Reserved {
			dbReserved = 1
		}

		if isNewWish {
			if err := dbQueries.CreateWish(ctx, sqlc.CreateWishParams{
				WishlistUuid: uuid,
				WishIndex:    int64(idx),
				Name:         wi.Name,
				Description:  wi.Description,
				ImageUrl:     wi.ImageUrl,
				Reserved:     dbReserved,
			}); err != nil {
				fmt.Printf("New Wish DB write failed: %v\n", err)
			}
		} else {
			if err := dbQueries.UpdateWish(ctx, sqlc.UpdateWishParams{
				Name:         wi.Name,
				Description:  wi.Description,
				ImageUrl:     wi.ImageUrl,
				Reserved:     dbReserved,
				WishlistUuid: uuid,
				WishIndex:    int64(idx),
			}); err != nil {
				fmt.Printf("Wish edit DB write failed: %v\n", err)
			}
		}

		// Add/Update links in db
		for lIndex, link := range links {
			// Do we actually really have to check, if each one already exist??
			_, err := dbQueries.GetLink(ctx, sqlc.GetLinkParams{uuid, int64(idx), int64(lIndex)})
			if err != nil {
				fmt.Printf("link '%v' doesn't exist\n", link)
				if err := dbQueries.CreateLink(ctx, sqlc.CreateLinkParams{uuid, int64(idx), int64(lIndex), link}); err != nil {
					fmt.Printf("Creating DB link failed: %v\n", err)
				}
			} else {
				fmt.Printf("link '%v' exists!\n", link)
				if err := dbQueries.UpdateLink(ctx, sqlc.UpdateLinkParams{link, uuid, int64(idx), int64(lIndex)}); err != nil {
					fmt.Printf("Update DB link failed: %v\n", err)
				}
			}
		}
		// Remove all db links with a link-index larger than len(links)-1 (links might have been deleted!)
		unusedLinks, err := dbQueries.GetUnusedLinks(ctx, sqlc.GetUnusedLinksParams{uuid, int64(idx), int64(len(links))})
		if err == nil {
			for _, ul := range unusedLinks {
				if err := dbQueries.DeleteLink(ctx, sqlc.DeleteLinkParams{uuid, int64(idx), ul.LinkIndex}); err != nil {
					fmt.Printf("Deleting DB link failed: %v\n", err)
				}
			}
		} else {
			fmt.Printf("Getting unused DB links failed: %v\n", err)
		}

		writeTemplateWish(w, r, "wish-item", idx, users[user].Wishlists[wlIndex].Wishes[idx], user == shortcuts[uuid].user, shortcuts[uuid].user)
	}
}

func initDatabase() {

	var err error
	db, err = sql.Open("sqlite3", "wishlist.sqlite3")
	if err != nil {
		fmt.Printf("Error opening the sqlite database: %v\n", err)
		return
	}

	// create tables if they don't exist yet
	if _, err = db.ExecContext(ctx, ddl); err != nil {
		fmt.Printf("Error creating the tables: %v\n", err)
		return
	}

	dbQueries = sqlc.New(db)
}

func populateDatabase() {

	dbQueries.DeleteAllUsers(ctx)
	dbQueries.DeleteAllWishlists(ctx)
	dbQueries.DeleteAllWishes(ctx)
	dbQueries.DeleteAllLinks(ctx)

	err, mUUID := newUUID()
	if err != nil {
		fmt.Println(err)
		return
	}
	err, mUUID2 := newUUID()
	if err != nil {
		fmt.Println(err)
		return
	}
	mWishlist := Wishlist{
		Title: "Wunschliste",
		UUID:  mUUID,
		Wishes: []Wish{
			{"Neuseeland", "Eine Reise nach Neuseeland", []string{"http://link1.com"}, defaultImage, false},
			{"Liebe", "Eine Maus, die mich lieb hat!", []string{"http://link1.com", "https://link2.de/blubb"}, "", true},
			{"Bär", "Ein liebes Glücksbärchen", nil, defaultImage, false},
		},
	}
	mWishlist2 := Wishlist{
		Title: "Geburtstags-Wunschliste",
		UUID:  mUUID2,
		Wishes: []Wish{
			{"A new webcam", "I just thought of the Logitech Brio 500...", []string{"https://www.amazon.de/dp/B07W5JKKFJ"}, "", false},
		},
	}
	gold := "https://www.muenzeoesterreich.at/var/em_plain_site/storage/images/_aliases/product_full/media/bilder/produktbilder/1.anlegen/handelsgold_mtt/1fach-dukaten-av/9572-4-ger-DE/1fach-dukaten-av.png"
	kinderwagen := "https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fi.otto.de%2Fi%2Fotto%2F16455872-f2bb-5a61-bfb2-261f5713a79a%3Fh%26%2361%3B520%26amp%3Bw%2661%3B551%26amp%3Bsm%2661%3Bclamp&f=1&nofb=1&ipt=492a936d362bfd9dfa8095c11c15251238c529f986d731b49d66a8a3f162df81&ipo=images"
	err, nUUID := newUUID()
	if err != nil {
		fmt.Println(err)
		return
	}
	nWishlist := Wishlist{
		Title: "Nadines Wunschliste",
		UUID:  nUUID,
		Wishes: []Wish{
			{"Ganz viel Gold und Reichtum", "Oder so. Ich muss da nochmal nachfragen :)", []string{"gold.de"}, gold, false},
			{"Ein Spaziergehpapabärchen", "Am liebsten jeden Morgen und nachmittags nochmal!", nil, kinderwagen, true},
			{"Ein frisch gesaugtes Bad und Schlafzimmer", "Das hätte ich gerne zu Weihnachten", nil, defaultImage, false},
		},
	}
	users["Maurice"] = userdata{
		passwordHash: hashPassword("Maurice", "passwort"),
		Wishlists:    []Wishlist{mWishlist, mWishlist2},
	}
	users["Nadine"] = userdata{
		passwordHash: hashPassword("Nadine", "passwort"),
		Wishlists:    []Wishlist{nWishlist},
	}

	shortcuts[mUUID] = shortcut{"Maurice", 0}
	shortcuts[mUUID2] = shortcut{"Maurice", 1}
	shortcuts[nUUID] = shortcut{"Nadine", 0}

	for username, data := range users {
		// Add user if it doesn't exist
		if _, err := dbQueries.GetUser(ctx, username); err != nil {
			if err := dbQueries.CreateUser(ctx, sqlc.CreateUserParams{username, data.passwordHash}); err != nil {
				fmt.Println(err)
			}
		}

		for _, wl := range data.Wishlists {
			// Add wishlist if it doesn't exist!
			if _, err := dbQueries.GetWishlist(ctx, wl.UUID); err != nil {
				if err := dbQueries.CreateWishlist(ctx, sqlc.CreateWishlistParams{wl.UUID, username, wl.Title}); err != nil {
					fmt.Println(err)
				}
			}

			for wIndex, w := range wl.Wishes {
				reserved := int64(0)
				if w.Reserved {
					reserved = 1
				}
				// Add wish if it doesn't exist
				if _, err := dbQueries.GetWish(ctx, sqlc.GetWishParams{wl.UUID, int64(wIndex)}); err != nil {
					if err := dbQueries.CreateWish(ctx, sqlc.CreateWishParams{
						WishlistUuid: wl.UUID,
						WishIndex:    int64(wIndex),
						Name:         w.Name,
						Description:  w.Description,
						ImageUrl:     w.ImageUrl,
						Reserved:     reserved,
					}); err != nil {
						fmt.Println(err)
					}
				}

				for lIndex, link := range w.Links {
					if _, err := dbQueries.GetLink(ctx, sqlc.GetLinkParams{wl.UUID, int64(wIndex), int64(lIndex)}); err != nil {
						if err := dbQueries.CreateLink(ctx, sqlc.CreateLinkParams{wl.UUID, int64(wIndex), int64(lIndex), link}); err != nil {
							fmt.Println(err)
						}
					}
				}
			}
		}
	}
}

func loadUserDataFromDB(username string) (userdata, error) {

	var newUser userdata
	dbUser, err := dbQueries.GetUser(ctx, username)
	if err != nil {
		fmt.Println(err)
		return newUser, err
	}

	newUser.passwordHash = dbUser.Passwordhash

	dbWishlists, err := dbQueries.GetWishlists(ctx, username)
	if err != nil {
		fmt.Println(err)
		return newUser, err
	}

	for _, wl := range dbWishlists {
		var wishlist Wishlist
		wishlist.Title = wl.Title
		wishlist.UUID = wl.Uuid

		dbWishes, err := dbQueries.GetWishes(ctx, wl.Uuid)
		if err != nil {
			fmt.Println(err)
			return newUser, err
		}

		for wIndex, w := range dbWishes {
			var wish Wish
			wish.Description = w.Description
			wish.ImageUrl = w.ImageUrl
			wish.Name = w.Name
			wish.Reserved = w.Reserved != 0

			dbLinks, err := dbQueries.GetLinks(ctx, sqlc.GetLinksParams{wl.Uuid, int64(wIndex)})
			if err != nil {
				fmt.Println(err)
				return newUser, err
			}

			for _, l := range dbLinks {
				wish.Links = append(wish.Links, l.Url)
			}

			wishlist.Wishes = append(wishlist.Wishes, wish)
		}

		newUser.Wishlists = append(newUser.Wishlists, wishlist)
	}

	return newUser, nil
}

func populateDataStructures() {

	dbUsers, err := dbQueries.GetUsers(ctx)
	if err != nil {
		fmt.Println(err)
	}
	for _, user := range dbUsers {
		if newUser, err := loadUserDataFromDB(user.Name); err == nil {
			users[user.Name] = newUser
			for wlIndex, wl := range users[user.Name].Wishlists {
				shortcuts[wl.UUID] = shortcut{user.Name, wlIndex}
			}
		}
	}
}

func main() {

	initDatabase()

	//populateDatabase()
	//populateDataStructures()

	// Shows /overview when logged in or /landingpage otherwise
	http.HandleFunc("/", allHandler)
	http.HandleFunc("/{uuid}", allHandler)
	// Shows a generic landing page
	http.HandleFunc("/landingpage", landingpageHandler)
	// Shows all available wishlists
	http.HandleFunc("/overview", overviewHandler)
	// Shows a specific wishlist
	http.HandleFunc("/wishlist/{uuid}", wishlistHandler)
	// Create new wishlist for user
	http.HandleFunc("/newwishlist", newwishlistHandler)
	// Show the edit view of a wishlist
	http.HandleFunc("/editwishlist/{uuid}", editwishlistHandler)
	// Shows the title of the wishlist instead of the edit version
	http.HandleFunc("/wishlisttitle/{uuid}", wishlisttitleHandler)
	// Transfer all changes to the wishlist to the data structure and db
	http.HandleFunc("/editwishlist/{uuid}/done", editwishlistDoneHandler)

	// Reserves a wish given the wishlist uuid and wish index
	http.HandleFunc("/reserve/{idx}", reserveWishHandler)
	// Creates a new wish. This is just an extended frontend view and will not change any data in the backend.
	http.HandleFunc("/new", newItemHandler)

	// Show wish idx of wishlist with a given uuid
	http.HandleFunc("/item/{idx}", itemHandler)
	// Delete wish idx of wishlist with a given uuid
	http.HandleFunc("/delete/{idx}", deleteHandler)
	// Show the edit-view of wish idx of wishlist with a given uuid
	http.HandleFunc("/edit/{idx}", editHandler)
	// Transfer all changes done in the edit of wish idx in wishlist of a given uuid
	http.HandleFunc("/edit/{idx}/done", editDoneHandler)
	// Add a new link in the current wish edit. This does not need to correspond to a specific wish and
	// will just extend the edit view by a new link field.
	http.HandleFunc("/addlink", addLinkHandler)

	// Shows a generic login page
	http.HandleFunc("/loginpage", loginPageHandler)
	// Handle user login with user/password provided
	http.HandleFunc("/login", loginHandler)
	// Handle logout of an active session
	http.HandleFunc("/logout", logoutHandler)

	//http.HandleFunc("readwishlist/{id}", readonlyWishlistHandler)
	http.ListenAndServe(":8080", nil)
}
