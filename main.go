package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"wishlist/sqlc"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/acme/autocert"

	// Use the regular slices.Collect(maps.Values()) as soon as go version 1.23 is supported by liteIDE!
	"golang.org/x/exp/maps"
)

type AccessState int

const (
	AccessSecret AccessState = iota
	AccessPublic
	AccessShared
)

type TemplateType int

const (
	TmplFullLandingpage TemplateType = iota
	TmplFullOverview
	TmplFullWishlist
	TmplFullVisited
	TmplOther
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
	Wish      Wish
	IsCreator bool
	Creator   string
	Access    AccessState
}

// ======================== Session Data

type session struct {
	username string
	expire   time.Time
}

// ======================== Internal Wishlist data structures

type Wish struct {
	ID          int64
	Name        string
	Description string
	Links       map[int64]string
	ImageUrl    string
	Reserved    bool
	Active      bool
	OrderIndex  int64
}

type Wishlist struct {
	Title  string
	UUID   string
	Access AccessState
	Wishes map[int64]Wish
}

type userdata struct {
	passwordHash []byte
	Wishlists    map[string]Wishlist
	// UUID -> time it was added/first-seen. Corresponds to the database entry!
	Visited map[string]time.Time
}

var (
	mu sync.Mutex

	users    = map[string]userdata{}
	sessions = map[string]session{}
	// Shortcuts are references from wishlist uuids to the user.
	// This avoids iterating all users when searching for a specific one.
	shortcuts = map[string]string{}

	funcMap = template.FuncMap{"newButton": newButton, "getUserOfWishlist": getUserOfWishlist, "getTitleOfWishlist": getTitleOfWishlist}

	allTemplates = map[TemplateType]*template.Template{
		TmplFullLandingpage: template.Must(template.ParseFiles("templates/main.html", "templates/landing-page.html")),
		TmplFullOverview:    template.Must(template.New("overview").Funcs(funcMap).ParseFiles("templates/main.html", "templates/overview.html", "templates/other.html")),
		TmplFullWishlist:    template.Must(template.New("testall").Funcs(funcMap).ParseFiles("templates/main.html", "templates/wishlist.html", "templates/other.html")),
		TmplFullVisited:     template.Must(template.New("visited").Funcs(funcMap).ParseFiles("templates/main.html", "templates/visited.html")),
		TmplOther:           template.Must(template.New("testall").Funcs(funcMap).ParseFiles("templates/other.html")),
	}

	//go:embed schema.sql
	ddl       string
	ctx       = context.Background()
	db        *sql.DB
	dbQueries *sqlc.Queries

	// This disables TLS, reloads templates for every request and makes cookie handling a lot more lax and insecure for local testing!
	debugMode = runInDebugMode()
)

// runInDebugMode checks, if the program is currently executed on a raspberry pi. If so, then it will force
// HTTPS and use the cached letsencrypt certificate.
// If not, we expect a debug build on the PC and use http and port 8080 for testing reasons.
func runInDebugMode() bool {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		fmt.Printf("RPI-Check: Opening /proc/cpuinfo failed: %v\n", err)
		return true
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		s := scanner.Text()
		if strings.HasPrefix(s, "Serial") {
			subS := strings.Split(s, ":")
			return strings.TrimSpace(subS[len(subS)-1]) == ""
		}
	}
	return true
}

// getTemplate returns the already loaded template in release or reloads it for every request in debug mode
func getTemplate(tmpl TemplateType) *template.Template {

	if debugMode {
		switch tmpl {
		case TmplFullLandingpage:
			return template.Must(template.ParseFiles(
				"templates/main.html", "templates/landing-page.html",
			))
		case TmplFullOverview:
			return template.Must(template.New("overview").Funcs(funcMap).ParseFiles(
				"templates/main.html", "templates/overview.html", "templates/other.html",
			))
		case TmplFullWishlist:
			return template.Must(template.New("testall").Funcs(funcMap).ParseFiles(
				"templates/main.html", "templates/wishlist.html", "templates/other.html",
			))
		case TmplFullVisited:
			return template.Must(template.New("visited").Funcs(funcMap).ParseFiles(
				"templates/main.html", "templates/visited.html",
			))
		case TmplOther:
			return template.Must(template.New("testall").Funcs(funcMap).ParseFiles(
				"templates/other.html",
			))
		}
	}

	return allTemplates[tmpl]
}

func (s *session) isExpired() bool {
	return s.expire.Before(time.Now())
}

func newButton(link, color, colorHighlight, side string) Button {
	return Button{link, color, colorHighlight, side}
}

func getUserOfWishlist(uuid string) string {
	if !loadWishlistFromDB(uuid) {
		fmt.Printf("Loading uuid '%v' from db failed\n")
		return "<unknown>"
	}
	if user, ok := shortcuts[uuid]; ok {
		return user
	}
	return "<unknown>"
}

func getTitleOfWishlist(uuid string) string {
	if !loadWishlistFromDB(uuid) {
		fmt.Printf("Loading uuid '%v' from db failed\n")
		return "<unknown>"
	}
	if user, ok := shortcuts[uuid]; ok {
		if wl, ok := users[user].Wishlists[uuid]; ok {
			return wl.Title
		}
	}
	return "<unknown>"
}

// This function will be used in the html/template to provide both wish and current index to the sub-template!
func (wish Wish) BundleWish(isCreator bool, access AccessState) TemplateWish {
	return TemplateWish{wish, isCreator, "", access}
}

func parseId(id string) int64 {
	idOut, err := strconv.Atoi(id)
	if err != nil {
		fmt.Printf("Parsing the id '%v' results in err '%v'\n", id, err)
		return -2
	}
	return int64(idOut)
}

// https://stackoverflow.com/questions/15130321/is-there-a-method-to-generate-a-uuid-with-go-language
func newUUID() (error, string) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error: ", err)
		return err, ""
	}
	return nil, fmt.Sprintf("%v-%X", time.Now().Unix(), b)
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

// =====================================================================================================================
// Functions to write to db and update the internal datastructure

func createNewWishlist(user string) error {
	mu.Lock()
	defer mu.Unlock()
	err, uuid := newUUID()
	if err != nil {
		fmt.Printf("Error creating new UUID: %v\n", err)
		return err
	}

	var wishlist Wishlist
	wishlist.UUID = uuid
	wishlist.Title = fmt.Sprintf("Wishlist %v", len(users[user].Wishlists))
	wishlist.Access = AccessPublic
	wishlist.Wishes = make(map[int64]Wish)
	users[user].Wishlists[uuid] = wishlist
	shortcuts[uuid] = user

	params := sqlc.CreateWishlistParams{
		Uuid:     uuid,
		UserName: user,
		Title:    wishlist.Title,
		Access:   int64(wishlist.Access),
	}
	if err := dbQueries.CreateWishlist(ctx, params); err != nil {
		fmt.Printf("Creating DB wishlist failed: %v\n", err)
		return err
	}

	return nil
}

func updateWishlist(user, uuid, title string, access AccessState) {
	mu.Lock()
	defer mu.Unlock()
	tmpWishlist := users[user].Wishlists[uuid]
	tmpWishlist.Title = title
	tmpWishlist.Access = access
	users[user].Wishlists[uuid] = tmpWishlist
	if err := dbQueries.UpdateWishlist(ctx, sqlc.UpdateWishlistParams{title, int64(access), uuid}); err != nil {
		fmt.Printf("Wishlist title update for db failed: %v\n", err)
	}
}

func deleteWishlist(user, uuid string) {
	mu.Lock()
	defer mu.Unlock()
	delete(users[user].Wishlists, uuid)
	if err := dbQueries.DeleteWishlist(ctx, uuid); err != nil {
		fmt.Printf("Deleting Wishlist in db with uuid: '%v' failed: %v\n", uuid, err)
	}
}

func reserveWish(uuid string, id, reserved int64) {
	mu.Lock()
	defer mu.Unlock()
	wish := users[shortcuts[uuid]].Wishlists[uuid].Wishes[id]
	wish.Reserved = reserved != 0
	users[shortcuts[uuid]].Wishlists[uuid].Wishes[id] = wish

	if err := dbQueries.SetWishReserve(ctx, sqlc.SetWishReserveParams{reserved, id}); err != nil {
		fmt.Printf("Wish reserve db write failed: %v\n", err)
	}
}

// addWish receives a partially filled Wish. Links are set to nil as they should be inserted into the database before
// adding them into the wish (to get the link id from the db)
// It returns the id of the newly created wish and an error if one occured.
func addWish(uuid string, wish Wish, wishId int64, links []string) (int64, error) {
	mu.Lock()
	defer mu.Unlock()
	dbReserved := int64(0)
	if wish.Reserved {
		dbReserved = 1
	}
	dbActive := int64(0)
	if wish.Active {
		dbActive = 1
	}

	// Insert with into db if it is a new wish
	if wishId == -1 {
		dbWish, err := dbQueries.CreateWish(ctx, sqlc.CreateWishParams{
			uuid, wish.Name, wish.Description, wish.ImageUrl, dbReserved, dbActive, wish.OrderIndex,
		})
		if err != nil {
			fmt.Printf("Creating new wish in db failed: %v\n", err)
			return -1, err
		}
		wishId = dbWish.ID
	} else {
		if err := dbQueries.UpdateWish(ctx, sqlc.UpdateWishParams{
			wish.Name, wish.Description, wish.ImageUrl, dbReserved, dbActive, wish.OrderIndex, wishId,
		}); err != nil {
			fmt.Printf("Updating wish in db failed: %v\n", err)
			return -1, err
		}
	}
	wish.ID = wishId

	// Remove all links of this wish from the database (if there are any)
	if err := dbQueries.DeleteWishLinks(ctx, wishId); err != nil {
		fmt.Printf("Deleting wish-links from the db failed: %v\n", err)
		return -1, err
	}

	// (Re-)Insert all links from the form into the database! Use the unique ID to make the connection to the wish!
	for _, l := range links {
		if l != "" {
			dbLink, err := dbQueries.CreateLink(ctx, sqlc.CreateLinkParams{wishId, l})
			if err != nil {
				fmt.Printf("Creating link in db failed: %v\n", err)
				return -1, err
			}
			// Use the unique db ID to add the link into the data structure
			wish.Links[dbLink.ID] = l
		}
	}

	// We just overwrite the current wish with the new correct one. Or add it to the map, whatever is the case!
	tmpUser := shortcuts[uuid]
	users[tmpUser].Wishlists[uuid].Wishes[wishId] = wish

	return wishId, nil
}

func deleteWish(uuid string, id int64) {
	mu.Lock()
	defer mu.Unlock()
	delete(users[shortcuts[uuid]].Wishlists[uuid].Wishes, id)
	if err := dbQueries.DeleteWish(ctx, id); err != nil {
		fmt.Printf("Delete wish DB write failed: %v\n", err)
	}
}

func loadUserFromDB(user string) bool {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := users[user]; ok {
		fmt.Printf("User %v is already loaded.\n", user)
		return true
	}
	userData, err := loadUserDataFromDB(user)
	if err == nil {
		users[user] = userData
		for wlUUID, _ := range users[user].Wishlists {
			shortcuts[wlUUID] = user
		}
		return true
	}
	return false
}

func updatePassword(user, password string) {
	mu.Lock()
	defer mu.Unlock()
	tmpUserdata := users[user]
	tmpUserdata.passwordHash = hashPassword(user, password)
	users[user] = tmpUserdata

	if err := dbQueries.UpdatePassword(ctx, sqlc.UpdatePasswordParams{tmpUserdata.passwordHash, user}); err != nil {
		fmt.Printf("Error updating password in db: %v\n", err)
	}
}

func createNewUser(user, password string) {
	mu.Lock()
	defer mu.Unlock()
	users[user] = userdata{
		passwordHash: hashPassword(user, password),
		Wishlists:    make(map[string]Wishlist),
	}
	if err := dbQueries.CreateUser(ctx, sqlc.CreateUserParams{user, users[user].passwordHash}); err != nil {
		fmt.Printf("Error creating new user in db: %v\n", err)
	}
}

// addVisitedWishlist adds the uuid as visited wishlist to the user.
func addVisitedWishlist(user, uuid string) {
	if _, ok := users[user].Visited[uuid]; !ok {
		if v, err := dbQueries.AddVisited(ctx, sqlc.AddVisitedParams{user, uuid}); err == nil {
			users[user].Visited[uuid] = v.Timestamp
		}
	}
}

func assignNewOrderIndices(user, uuid string, ids []string) {
	mu.Lock()
	defer mu.Unlock()
	wl := users[user].Wishlists[uuid]
	for i, idStr := range ids {
		id := parseId(idStr)
		w := wl.Wishes[id]
		w.OrderIndex = int64(i)
		wl.Wishes[id] = w
		if err := dbQueries.SetWishOrderIndex(ctx, sqlc.SetWishOrderIndexParams{int64(i), id}); err != nil {
			fmt.Printf("Error updating order_index in db: %v\n", err)
		}
	}
	users[user].Wishlists[uuid] = wl
}

func loadUserDataFromDB(username string) (userdata, error) {

	var newUser userdata
	newUser.Wishlists = make(map[string]Wishlist)
	newUser.Visited = make(map[string]time.Time)

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
		wishlist.Access = AccessState(wl.Access)
		wishlist.Wishes = make(map[int64]Wish)

		dbWishes, err := dbQueries.GetWishes(ctx, wl.Uuid)
		if err != nil {
			fmt.Println(err)
			return newUser, err
		}

		for _, w := range dbWishes {
			var wish Wish
			wish.ID = w.ID
			wish.Links = make(map[int64]string)
			wish.Description = w.Description
			wish.ImageUrl = w.ImageUrl
			wish.Name = w.Name
			wish.Reserved = w.Reserved != 0
			wish.Active = w.Active != 0
			wish.OrderIndex = w.OrderIndex

			dbLinks, err := dbQueries.GetLinks(ctx, w.ID)
			if err != nil {
				fmt.Println(err)
				return newUser, err
			}

			for _, l := range dbLinks {
				wish.Links[l.ID] = l.Url
			}

			wishlist.Wishes[w.ID] = wish
		}

		newUser.Wishlists[wl.Uuid] = wishlist
	}

	if dbVisited, err := dbQueries.GetAllVisited(ctx, username); err == nil {
		for _, v := range dbVisited {
			newUser.Visited[v.WishlistUuid] = v.Timestamp
		}
	} else {
		fmt.Println(err)
	}

	return newUser, nil
}

// =====================================================================================================================

func loadWishlistFromDB(uuid string) bool {
	dbwl, err := dbQueries.GetWishlist(ctx, uuid)
	if err != nil {
		fmt.Printf("Wishlist with uuid '%v' not found in DB: %v\n", uuid, err)
	} else {
		return loadUserFromDB(dbwl.UserName)
	}
	return false
}

// landingPageHandler handles the landing page. If the user is not authenticated, it will show the login screen.
// otherwise it will show the users wishlists.
func allHandler(w http.ResponseWriter, r *http.Request) {

	user, authenticated, _ := checkAuthentication(r)

	uuid := r.PathValue("uuid")
	// We do not check the user or run authentication here because this page can be opened without being logged in.
	uuidOK := checkWishlistUUID(uuid)

	// Check the DB if there is a valid wishlist
	if !uuidOK && uuid != "" {
		/*
			dbwl, err := dbQueries.GetWishlist(ctx, uuid)
			if err != nil {
				fmt.Printf("Wishlist with uuid '%v' not found in DB: %v\n", uuid, err)
			} else {
				uuidOK = loadUserFromDB(dbwl.UserName)
			}
		*/
		uuidOK = loadWishlistFromDB(uuid)
	}

	// If we only show one wishlist, it doesn't matter if the user is authenticated or not!
	if uuidOK {
		wlUser := shortcuts[uuid]
		wishlist := users[wlUser].Wishlists[uuid]

		// Wishlists set to 'Secret' can not be accessed externally!
		if wishlist.Access != AccessSecret || user == wlUser {

			sortedList := maps.Values(wishlist.Wishes)
			sort.Slice(sortedList, func(i, j int) bool { return sortedList[i].OrderIndex < sortedList[j].OrderIndex })

			// Only save wishlists of other users
			if user != wlUser {
				addVisitedWishlist(user, uuid)
			}

			data := struct {
				Title         string
				UUID          string
				Wishes        []Wish
				Authenticated bool
				Username      string
				IsCreator     bool
				Creator       string
				Access        AccessState
			}{
				Title:         wishlist.Title,
				UUID:          wishlist.UUID,
				Wishes:        sortedList,
				Authenticated: authenticated,
				Username:      user,
				IsCreator:     user == wlUser,
				Creator:       wlUser,
				Access:        wishlist.Access,
			}

			if r.Header.Get("HX-Request") == "true" {
				if err := getTemplate(TmplFullWishlist).ExecuteTemplate(w, "content", data); err != nil {
					fmt.Println(err)
				}
			} else {
				if err := getTemplate(TmplFullWishlist).ExecuteTemplate(w, "all", data); err != nil {
					fmt.Println(err)
				}
			}

			return
		}
	}

	data := struct {
		Wishlists     map[string]Wishlist
		Authenticated bool
		Username      string
	}{
		Wishlists:     nil,
		Authenticated: authenticated,
		Username:      user,
	}

	// Authenticated users get the wishlist overview
	if authenticated {
		data.Wishlists = users[user].Wishlists
		if err := getTemplate(TmplFullOverview).ExecuteTemplate(w, "all", data); err != nil {
			fmt.Println(err)
		}
		return
	}

	// For all other cases, just show the landing page!
	if err := getTemplate(TmplFullLandingpage).ExecuteTemplate(w, "all", data); err != nil {
		fmt.Println(err)
	}
}

// landingPageHandler handles the landing page. If the user is not authenticated, it will show the login screen.
// otherwise it will show the users wishlists.
func landingpageHandler(w http.ResponseWriter, r *http.Request) {
	if err := getTemplate(TmplFullLandingpage).ExecuteTemplate(w, "content", nil); err != nil {
		fmt.Println(err)
	}
}

func overviewHandler(w http.ResponseWriter, r *http.Request) {
	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {
		if err := getTemplate(TmplFullOverview).ExecuteTemplate(w, "content", users[user]); err != nil {
			fmt.Println(err)
		}
	}
}

func visitedHandler(w http.ResponseWriter, r *http.Request) {
	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {

		sortedUUIDs := maps.Keys(users[user].Visited)
		sort.Slice(sortedUUIDs, func(i, j int) bool {
			return users[user].Visited[sortedUUIDs[i]].Before(users[user].Visited[sortedUUIDs[j]])
		})

		if err := getTemplate(TmplFullVisited).ExecuteTemplate(w, "content", sortedUUIDs); err != nil {
			fmt.Println(err)
		}
	}
}

// checkWishlistUUID checks if the uuid corresponds to a valid user and there exists a wishlist with the identical uuid!
func checkWishlistUUID(uuid string) bool {
	if user, ok := shortcuts[uuid]; ok {
		if userdata, ok := users[user]; ok {
			_, ok = userdata.Wishlists[uuid]
			return ok
		}
	}
	return false
}

func wishlistHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {

		uuid := r.PathValue("uuid")
		if !checkWishlistUUID(uuid) || shortcuts[uuid] != user {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}

		wlUser := shortcuts[uuid]
		wishlist := users[wlUser].Wishlists[uuid]

		sortedList := maps.Values(wishlist.Wishes)
		sort.Slice(sortedList, func(i, j int) bool { return sortedList[i].OrderIndex < sortedList[j].OrderIndex })

		data := struct {
			Title     string
			UUID      string
			Access    AccessState
			Wishes    []Wish
			IsCreator bool
			Creator   string
		}{
			Title:     wishlist.Title,
			UUID:      wishlist.UUID,
			Access:    wishlist.Access,
			Wishes:    sortedList,
			IsCreator: user == wlUser,
			Creator:   wlUser,
		}

		if err := getTemplate(TmplFullWishlist).ExecuteTemplate(w, "content", data); err != nil {
			fmt.Println(err)
		}
	}
}

func newwishlistHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {

		createNewWishlist(user)
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	}
}

func editwishlistHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok {
		uuid := r.PathValue("uuid")
		if !checkWishlistUUID(uuid) || shortcuts[uuid] != user {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}

		switch r.Method {
		case http.MethodGet:

			if r.Header.Get("HX-Request") == "true" {
				if err := getTemplate(TmplFullWishlist).ExecuteTemplate(w, "wishlist-edit", users[user].Wishlists[uuid]); err != nil {
					fmt.Println(err)
				}
				return
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
		case http.MethodPost:

			if err := r.ParseForm(); err != nil {
				http.Error(w, "Unable to parse form", http.StatusBadRequest)
				return
			}

			fmt.Printf("Wishlist UUID '%v' edited by user %v\n", uuid, user)
			access := AccessPublic
			switch r.FormValue("access") {
			case "secret":
				access = AccessSecret
			case "public":
				access = AccessPublic
			case "shared":
				access = AccessShared
			}

			if r.Header.Get("HX-Request") == "true" {
				updateWishlist(user, uuid, r.FormValue("name"), access)
				//renderWishlistTitle(w, users[user].Wishlists[uuid], true)
				//return
			}
			//http.Redirect(w, r, "/wishlisttitle/"+uuid, http.StatusOK)

			w.Header().Set("HX-Redirect", "/"+uuid)
			w.WriteHeader(http.StatusOK)
		}
	}
}

func renderWishlistTitle(w http.ResponseWriter, wishlist Wishlist, isCreator bool) {
	if err := getTemplate(TmplFullWishlist).ExecuteTemplate(w, "wishlist-title", struct {
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
		if !checkWishlistUUID(uuid) || shortcuts[uuid] != user {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}

		if r.Header.Get("HX-Request") == "true" {
			renderWishlistTitle(w, users[user].Wishlists[uuid], true)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func deletewishlistHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodPut {
		uuid := r.PathValue("uuid")
		if !checkWishlistUUID(uuid) || shortcuts[uuid] != user {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}

		fmt.Printf("Wishlist UUID '%v' deleted by user %v\n", uuid, user)

		deleteWishlist(user, uuid)

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

		// remove the shortcuts from the users wishlist uuids to user
		for uuid, _ := range users[user].Wishlists {
			delete(shortcuts, uuid)
		}

		// remove userdata from memory. Must be reloaded from db the next time this user logs in
		delete(users, user)

		sameSite := http.SameSiteStrictMode
		secure := true
		if debugMode {
			sameSite = http.SameSiteLaxMode
			secure = false
		}

		// We need to let the client know that the cookie is expired
		// In the response, we set the session token to an empty
		// value and set its expiry as the current time
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    "",
			Expires:  time.Now(),
			Path:     "/",      // Ensures the cookie is available throughout the site
			SameSite: sameSite, // Use Lax, or change to Strict or None as per your needs
			Secure:   secure,   // Must be true if SameSite=None (requires HTTPS)
			HttpOnly: true,     // Prevents JavaScript from accessing the cookie
		})

		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	}
}

func changepasswordHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok {

		switch r.Method {
		case http.MethodGet:
			if r.Header.Get("HX-Request") == "true" {
				if err := getTemplate(TmplOther).ExecuteTemplate(w, "changepassword", nil); err != nil {
					fmt.Println(err)
				}
				return
			}
		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Unable to parse form", http.StatusBadRequest)
				return
			}
			oldHash := hashPassword(user, strings.TrimSpace(r.FormValue("old-password")))
			newPassword1 := strings.TrimSpace(r.FormValue("new-password1"))
			newPassword2 := strings.TrimSpace(r.FormValue("new-password2"))

			// Wrong old password or New passwords are different
			if !bytes.Equal(oldHash, users[user].passwordHash) || newPassword1 != newPassword2 {
				if r.Header.Get("HX-Request") == "true" {
					if err := getTemplate(TmplOther).ExecuteTemplate(w, "changepassword-error", nil); err != nil {
						fmt.Println(err)
					}
					return
				}
			}

			updatePassword(user, newPassword1)

			w.Header().Set("HX-Redirect", "/")
			w.WriteHeader(http.StatusOK)
		}

	}
}

func newuserHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok {
		// Make sure ONLY I can create new users right now.
		if user != "Maurice" {
			return
		}

		switch r.Method {
		case http.MethodGet:
			if r.Header.Get("HX-Request") == "true" {
				if err := getTemplate(TmplOther).ExecuteTemplate(w, "newuser", nil); err != nil {
					fmt.Println(err)
				}
				return
			}
		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Unable to parse form", http.StatusBadRequest)
				return
			}
			newUser := strings.TrimSpace(r.FormValue("email"))
			newPassword := strings.TrimSpace(r.FormValue("password"))

			// If the username is not empty and the user doesn't exist yet
			if _, ok := users[newUser]; !ok && newUser != "" {
				createNewUser(newUser, newPassword)
			}
		}
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	}
}
func writeTemplateWish(w http.ResponseWriter, r *http.Request, template string, wish Wish, isCreator bool, creator string, access AccessState) {

	if r.Header.Get("HX-Request") == "true" {
		if err := getTemplate(TmplOther).ExecuteTemplate(w, template, TemplateWish{
			Wish:      wish,
			IsCreator: isCreator,
			Creator:   creator,
			Access:    access,
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

		id := parseId(r.PathValue("id"))

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

		wlUser := shortcuts[uuid]
		dbReserve := int64(0)
		reserveStr := "unreserves"
		reserve := r.FormValue("reserve") == "true"
		if reserve {
			dbReserve = 1
			reserveStr = "reserves"
		}
		fmt.Printf("User '%v' %v wish (id: %v) in wishlist with uuid: %v by creator '%v'\n", user, reserveStr, id, uuid, wlUser)

		reserveWish(uuid, id, dbReserve)
		wl := users[wlUser].Wishlists[uuid]
		writeTemplateWish(w, r, "wish-item", wl.Wishes[id], user == wlUser, wlUser, wl.Access)
	}
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {

	// Delete an item!
	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodPut {
		id := parseId(r.PathValue("id"))
		// possibly a cancel on a newly created item. Lets just return nothing instead!
		if id < 0 {
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		uuid := r.FormValue("wishlist-uuid")
		if !checkWishlistUUID(uuid) || shortcuts[uuid] != user {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}

		fmt.Printf("Delete wish %v for user '%v' and wishlist with uuid: %v\n", id, user, uuid)

		deleteWish(uuid, id)

		// Return nothing. That should just remove the currently edited item!
	}
}

func itemHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {
		id := parseId(r.PathValue("id"))

		// possibly a cancel on a newly created item. Lets just return nothing instead!
		if id < 0 {
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		uuid := r.FormValue("wishlist-uuid")
		if !checkWishlistUUID(uuid) || shortcuts[uuid] != user {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}
		fmt.Printf("Show item %v for user '%v' and wishlist with uuid: %v\n", id, user, uuid)

		wl := users[user].Wishlists[uuid]
		writeTemplateWish(w, r, "wish-item", wl.Wishes[id], true, shortcuts[uuid], wl.Access)
	}
}

func editHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok {

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		uuid := r.FormValue("wishlist-uuid")
		if !checkWishlistUUID(uuid) || shortcuts[uuid] != user {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}

		switch r.Method {
		case http.MethodGet:
			id := parseId(r.PathValue("id"))
			if id < 0 {
				return
			}

			fmt.Printf("Show the edit of item %v for user '%v' and wishlist with uuid: %v\n", id, user, uuid)

			if r.Header.Get("HX-Request") == "true" {
				if err := getTemplate(TmplOther).ExecuteTemplate(w, "wish-edit", users[user].Wishlists[uuid].Wishes[id]); err != nil {
					fmt.Println(err)
				}
				return
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
		case http.MethodPost:
			id := parseId(r.PathValue("id"))
			if id == -2 {
				http.Error(w, "Unable to parse wish id", http.StatusBadRequest)
				return
			}

			fmt.Printf("Editing Done for item %v for user '%v' and wishlist with uuid: %v\n", id, user, uuid)

			reserved := false
			orderIndex := int64(len(users[user].Wishlists[uuid].Wishes))
			if id >= 0 {
				reserved = users[user].Wishlists[uuid].Wishes[id].Reserved
				orderIndex = users[user].Wishlists[uuid].Wishes[id].OrderIndex
			}

			tmpWish := Wish{
				ID:          id,
				Name:        r.FormValue("name"),
				Description: r.FormValue("description"),
				Links:       make(map[int64]string),
				ImageUrl:    r.FormValue("imageUrl"),
				Reserved:    reserved,
				Active:      r.FormValue("active") != "",
				OrderIndex:  orderIndex,
			}

			wishId, err := addWish(uuid, tmpWish, id, r.Form["link"])
			if err != nil {
				http.Error(w, "Error updating/adding wish", http.StatusInternalServerError)
				return
			}

			wl := users[user].Wishlists[uuid]
			writeTemplateWish(w, r, "wish-item", wl.Wishes[wishId], true, shortcuts[uuid], wl.Access)
		}
	}
}

func addLinkHandler(w http.ResponseWriter, r *http.Request) {

	if _, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {

		if r.Header.Get("HX-Request") == "true" {
			if err := getTemplate(TmplOther).ExecuteTemplate(w, "link", ""); err != nil {
				fmt.Println(err)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		if r.Header.Get("HX-Request") == "true" {
			if err := getTemplate(TmplOther).ExecuteTemplate(w, "login", nil); err != nil {
				fmt.Println(err)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	case http.MethodPost:
		var err error
		if r.Method == http.MethodPost {

			if err := r.ParseForm(); err != nil {
				http.Error(w, "Unable to parse form", http.StatusBadRequest)
				if err := getTemplate(TmplOther).ExecuteTemplate(w, "login-error", nil); err != nil {
					fmt.Println(err)
				}
				return
			}

			user := strings.TrimSpace(r.FormValue("email"))
			password := strings.TrimSpace(r.FormValue("password"))
			pHash := hashPassword(user, password)

			// First check, if the user is already loaded from db
			userData, ok := users[user]
			if !ok {
				if !loadUserFromDB(user) {
					fmt.Printf("Error loading userdata from db: %v\n", err)
					w.WriteHeader(http.StatusOK)
					if err := getTemplate(TmplOther).ExecuteTemplate(w, "login-error", nil); err != nil {
						fmt.Println(err)
					}
					return
				}
				// Reload the user data because for the first try, there wasn't any user data loaded from the db yet.
				userData, _ = users[user]
			}

			if !bytes.Equal(pHash, userData.passwordHash) {
				fmt.Printf("User '%v' exists, but wrong password.\n", user)
				w.WriteHeader(http.StatusOK)
				if err := getTemplate(TmplOther).ExecuteTemplate(w, "login-error", nil); err != nil {
					fmt.Println(err)
				}
				return
			}

			err, sessionToken := newUUID()
			if err != nil {
				fmt.Printf("Error when generating a new uuid: %v\n", err)
				w.WriteHeader(http.StatusUnauthorized)
				if err := getTemplate(TmplOther).ExecuteTemplate(w, "login-error", nil); err != nil {
					fmt.Println(err)
				}
				return
			}
			// Expires after 30 days
			sessionExpire := time.Now().Add(24 * time.Hour * 30)

			sessions[sessionToken] = session{
				username: user,
				expire:   sessionExpire,
			}

			fmt.Printf("New session for user '%v'\n", user)

			sameSite := http.SameSiteStrictMode
			secure := true
			if debugMode {
				sameSite = http.SameSiteLaxMode
				secure = false
			}

			http.SetCookie(w, &http.Cookie{
				Name:     "session_token",
				Value:    sessionToken,
				Expires:  sessionExpire,
				Path:     "/",      // Ensures the cookie is available throughout the site
				SameSite: sameSite, // Use Lax, or change to Strict or None as per your needs
				Secure:   secure,   // Must be true if SameSite=None (requires HTTPS)
				HttpOnly: true,     // Prevents JavaScript from accessing the cookie
			})

			// User authenticated and everything is OK
			w.Header().Set("HX-Redirect", "/")
			w.WriteHeader(http.StatusOK)
		}
	}
}

func newItemHandler(w http.ResponseWriter, r *http.Request) {

	if _, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodGet {

		if r.Header.Get("HX-Request") == "true" {
			if err := getTemplate(TmplOther).ExecuteTemplate(w, "wish-edit", Wish{-1, "", "", nil, "", false, true, 0}); err != nil {
				fmt.Println(err)
			}
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func editDoneHandler(w http.ResponseWriter, r *http.Request) {

	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodPost {
		id := parseId(r.PathValue("id"))
		if id == -2 {
			http.Error(w, "Unable to parse wish id", http.StatusBadRequest)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		uuid := r.FormValue("wishlist-uuid")
		if !checkWishlistUUID(uuid) || shortcuts[uuid] != user {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}
		fmt.Printf("Editing Done for item %v for user '%v' and wishlist with uuid: %v\n", id, user, uuid)

		reserved := false
		orderIndex := int64(0)
		if id >= 0 {
			reserved = users[user].Wishlists[uuid].Wishes[id].Reserved
			orderIndex = int64(len(users[user].Wishlists[uuid].Wishes))
		}

		tmpWish := Wish{
			ID:          id,
			Name:        r.FormValue("name"),
			Description: r.FormValue("description"),
			Links:       make(map[int64]string),
			ImageUrl:    r.FormValue("imageUrl"),
			Reserved:    reserved,
			Active:      r.FormValue("active") != "",
			OrderIndex:  orderIndex,
		}

		wishId, err := addWish(uuid, tmpWish, id, r.Form["link"])
		if err != nil {
			http.Error(w, "Error updating/adding wish", http.StatusInternalServerError)
			return
		}

		wl := users[user].Wishlists[uuid]
		writeTemplateWish(w, r, "wish-item", wl.Wishes[wishId], true, shortcuts[uuid], wl.Access)
	}
}

func sortedHandler(w http.ResponseWriter, r *http.Request) {
	if user, ok := handleUserAuthentication(w, r); ok && r.Method == http.MethodPost {

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		uuid := r.FormValue("wishlist-uuid")
		if !checkWishlistUUID(uuid) || shortcuts[uuid] != user {
			fmt.Printf("Wishlist UUID '%v' doesn't exist or results in invalid user or index\n", uuid)
			return
		}
		fmt.Printf("Re-Ordering wishes by user %v in wishlist with uuid: '%v'\n", user, uuid)

		assignNewOrderIndices(user, uuid, r.Form["item"])
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

func main() {

	var certManager autocert.Manager
	var server *http.Server
	if !debugMode {
		certManager = autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist("wuenscheahoi.duckdns.org", "www.wuenscheahoi.duckdns.org"),
			Cache:      autocert.DirCache("certs"),
		}

		server = &http.Server{
			Addr: ":https",
			TLSConfig: &tls.Config{
				GetCertificate: certManager.GetCertificate,
				MinVersion:     tls.VersionTLS13,
			},
		}
	}

	initDatabase()

	// Shows /overview when logged in or /landingpage otherwise
	http.HandleFunc("/", allHandler)
	http.HandleFunc("/{uuid}", allHandler)
	// Shows a generic landing page
	http.HandleFunc("/landingpage", landingpageHandler)
	// Shows all available wishlists
	http.HandleFunc("/overview", overviewHandler)
	// Shows a list of visited wishlists
	http.HandleFunc("/visited", visitedHandler)
	// Shows a specific wishlist
	http.HandleFunc("/wishlist/{uuid}", wishlistHandler)
	// Create new wishlist for user
	http.HandleFunc("/newwishlist", newwishlistHandler)
	// Show the edit view of a wishlist and transfer all changes to the wishlist to the data structure and db
	http.HandleFunc("/editwishlist/{uuid}", editwishlistHandler)
	// Shows the title of the wishlist instead of the edit version
	http.HandleFunc("/wishlisttitle/{uuid}", wishlisttitleHandler)
	// Delete a wishlist
	http.HandleFunc("/deletewishlist/{uuid}", deletewishlistHandler)

	// Reserves a wish given the wishlist uuid and wish index
	http.HandleFunc("/reserve/{id}", reserveWishHandler)
	// Creates a new wish. This is just an extended frontend view and will not change any data in the backend.
	http.HandleFunc("/new", newItemHandler)

	// Show wish idx of wishlist with a given uuid
	http.HandleFunc("/item/{id}", itemHandler)
	// Delete wish idx of wishlist with a given uuid
	http.HandleFunc("/delete/{id}", deleteHandler)
	// Handler to edit the wish id of wishlist with a given uuid
	http.HandleFunc("/edit/{id}", editHandler)
	// Add a new link in the current wish edit. This does not need to correspond to a specific wish and
	// will just extend the edit view by a new link field.
	http.HandleFunc("/addlink", addLinkHandler)

	// Handles login page and user login with user/password provided
	http.HandleFunc("/login", loginHandler)
	// Handle logout of an active session
	http.HandleFunc("/logout", logoutHandler)
	// Change password page and actual data input handler. Get/Post
	http.HandleFunc("/changepassword", changepasswordHandler)
	// Create new user. This is shown to limited users
	http.HandleFunc("/newuser", newuserHandler)

	// Handles the re-ordering in the frontend. This is called by sortable after
	// elements are reordered. A list of wish-ids is provided and updated in the backend
	http.HandleFunc("/sorted", sortedHandler)

	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./favicon.ico")
	})

	if !debugMode {
		go http.ListenAndServe(":http", certManager.HTTPHandler(nil))
		log.Fatal(server.ListenAndServeTLS("", ""))
	} else {
		http.ListenAndServe(":8080", nil)
	}
}
