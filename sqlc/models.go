// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0

package sqlc

type Link struct {
	ID        int64
	WishID    int64
	LinkIndex int64
	Url       string
}

type User struct {
	Name         string
	Passwordhash []byte
}

type Wish struct {
	ID           int64
	WishlistUuid string
	WishIndex    int64
	Name         string
	Description  string
	ImageUrl     string
	Reserved     int64
}

type Wishlist struct {
	Uuid     string
	UserName string
	Title    string
}
