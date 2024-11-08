// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: query.sql

package sqlc

import (
	"context"
)

const createLink = `-- name: CreateLink :one
INSERT INTO links (
    wish_id, url
)
VALUES (
    ?, ?
)
RETURNING id, wish_id, url
`

type CreateLinkParams struct {
	WishID int64
	Url    string
}

func (q *Queries) CreateLink(ctx context.Context, arg CreateLinkParams) (Link, error) {
	row := q.db.QueryRowContext(ctx, createLink, arg.WishID, arg.Url)
	var i Link
	err := row.Scan(&i.ID, &i.WishID, &i.Url)
	return i, err
}

const createUser = `-- name: CreateUser :exec
INSERT INTO users (
    name, passwordhash
) VALUES(
    ?, ?
)
`

type CreateUserParams struct {
	Name         string
	Passwordhash []byte
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) error {
	_, err := q.db.ExecContext(ctx, createUser, arg.Name, arg.Passwordhash)
	return err
}

const createWish = `-- name: CreateWish :one
INSERT INTO wishes(
    wishlist_uuid, name, description, image_url, reserved, active, order_index
) VALUES (
    ?, ?, ?, ?, ?, ?, ?
)
RETURNING id, wishlist_uuid, name, description, image_url, reserved, active, order_index
`

type CreateWishParams struct {
	WishlistUuid string
	Name         string
	Description  string
	ImageUrl     string
	Reserved     int64
	Active       int64
	OrderIndex   int64
}

func (q *Queries) CreateWish(ctx context.Context, arg CreateWishParams) (Wish, error) {
	row := q.db.QueryRowContext(ctx, createWish,
		arg.WishlistUuid,
		arg.Name,
		arg.Description,
		arg.ImageUrl,
		arg.Reserved,
		arg.Active,
		arg.OrderIndex,
	)
	var i Wish
	err := row.Scan(
		&i.ID,
		&i.WishlistUuid,
		&i.Name,
		&i.Description,
		&i.ImageUrl,
		&i.Reserved,
		&i.Active,
		&i.OrderIndex,
	)
	return i, err
}

const createWishlist = `-- name: CreateWishlist :exec
INSERT INTO wishlists (
    uuid, user_name, title, access
) VALUES (
    ?, ?, ?, ?
)
`

type CreateWishlistParams struct {
	Uuid     string
	UserName string
	Title    string
	Access   int64
}

func (q *Queries) CreateWishlist(ctx context.Context, arg CreateWishlistParams) error {
	_, err := q.db.ExecContext(ctx, createWishlist,
		arg.Uuid,
		arg.UserName,
		arg.Title,
		arg.Access,
	)
	return err
}

const deleteAllLinks = `-- name: DeleteAllLinks :exec
DELETE FROM links
`

func (q *Queries) DeleteAllLinks(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllLinks)
	return err
}

const deleteAllUsers = `-- name: DeleteAllUsers :exec
DELETE FROM users
`

func (q *Queries) DeleteAllUsers(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllUsers)
	return err
}

const deleteAllWishes = `-- name: DeleteAllWishes :exec
DELETE FROM wishes
WHERE wishlist_uuid = ?
`

func (q *Queries) DeleteAllWishes(ctx context.Context, wishlistUuid string) error {
	_, err := q.db.ExecContext(ctx, deleteAllWishes, wishlistUuid)
	return err
}

const deleteAllWishlists = `-- name: DeleteAllWishlists :exec
DELETE FROM wishlists
WHERE user_name = ?
`

func (q *Queries) DeleteAllWishlists(ctx context.Context, userName string) error {
	_, err := q.db.ExecContext(ctx, deleteAllWishlists, userName)
	return err
}

const deleteLink = `-- name: DeleteLink :exec
DELETE FROM links
WHERE wish_id = ? AND id = ?
`

type DeleteLinkParams struct {
	WishID int64
	ID     int64
}

func (q *Queries) DeleteLink(ctx context.Context, arg DeleteLinkParams) error {
	_, err := q.db.ExecContext(ctx, deleteLink, arg.WishID, arg.ID)
	return err
}

const deleteUser = `-- name: DeleteUser :exec
DELETE FROM users
WHERE name = ?
`

func (q *Queries) DeleteUser(ctx context.Context, name string) error {
	_, err := q.db.ExecContext(ctx, deleteUser, name)
	return err
}

const deleteWish = `-- name: DeleteWish :exec
DELETE FROM wishes
WHERE id = ?
`

func (q *Queries) DeleteWish(ctx context.Context, id int64) error {
	_, err := q.db.ExecContext(ctx, deleteWish, id)
	return err
}

const deleteWishLinks = `-- name: DeleteWishLinks :exec
DELETE FROM links
WHERE wish_id = ?
`

func (q *Queries) DeleteWishLinks(ctx context.Context, wishID int64) error {
	_, err := q.db.ExecContext(ctx, deleteWishLinks, wishID)
	return err
}

const deleteWishlist = `-- name: DeleteWishlist :exec
DELETE FROM wishlists
WHERE uuid = ?
`

func (q *Queries) DeleteWishlist(ctx context.Context, uuid string) error {
	_, err := q.db.ExecContext(ctx, deleteWishlist, uuid)
	return err
}

const getLink = `-- name: GetLink :one
SELECT id, wish_id, url FROM links
WHERE wish_id = ? AND id = ? LIMIT 1
`

type GetLinkParams struct {
	WishID int64
	ID     int64
}

func (q *Queries) GetLink(ctx context.Context, arg GetLinkParams) (Link, error) {
	row := q.db.QueryRowContext(ctx, getLink, arg.WishID, arg.ID)
	var i Link
	err := row.Scan(&i.ID, &i.WishID, &i.Url)
	return i, err
}

const getLinks = `-- name: GetLinks :many
SELECT id, wish_id, url FROM links
WHERE wish_id = ?
ORDER BY id
`

func (q *Queries) GetLinks(ctx context.Context, wishID int64) ([]Link, error) {
	rows, err := q.db.QueryContext(ctx, getLinks, wishID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Link
	for rows.Next() {
		var i Link
		if err := rows.Scan(&i.ID, &i.WishID, &i.Url); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getUser = `-- name: GetUser :one
SELECT name, passwordhash FROM users
WHERE name = ? LIMIT 1
`

func (q *Queries) GetUser(ctx context.Context, name string) (User, error) {
	row := q.db.QueryRowContext(ctx, getUser, name)
	var i User
	err := row.Scan(&i.Name, &i.Passwordhash)
	return i, err
}

const getUsers = `-- name: GetUsers :many
SELECT name, passwordhash FROM users
`

func (q *Queries) GetUsers(ctx context.Context) ([]User, error) {
	rows, err := q.db.QueryContext(ctx, getUsers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []User
	for rows.Next() {
		var i User
		if err := rows.Scan(&i.Name, &i.Passwordhash); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getWish = `-- name: GetWish :one
SELECT id, wishlist_uuid, name, description, image_url, reserved, active, order_index FROM wishes
WHERE id = ? LIMIT 1
`

func (q *Queries) GetWish(ctx context.Context, id int64) (Wish, error) {
	row := q.db.QueryRowContext(ctx, getWish, id)
	var i Wish
	err := row.Scan(
		&i.ID,
		&i.WishlistUuid,
		&i.Name,
		&i.Description,
		&i.ImageUrl,
		&i.Reserved,
		&i.Active,
		&i.OrderIndex,
	)
	return i, err
}

const getWishes = `-- name: GetWishes :many
SELECT id, wishlist_uuid, name, description, image_url, reserved, active, order_index FROM wishes
WHERE wishlist_uuid = ?
ORDER BY order_index, id
`

func (q *Queries) GetWishes(ctx context.Context, wishlistUuid string) ([]Wish, error) {
	rows, err := q.db.QueryContext(ctx, getWishes, wishlistUuid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Wish
	for rows.Next() {
		var i Wish
		if err := rows.Scan(
			&i.ID,
			&i.WishlistUuid,
			&i.Name,
			&i.Description,
			&i.ImageUrl,
			&i.Reserved,
			&i.Active,
			&i.OrderIndex,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getWishlist = `-- name: GetWishlist :one
SELECT uuid, user_name, title, timestamp, access FROM wishlists
WHERE uuid = ? LIMIT 1
`

func (q *Queries) GetWishlist(ctx context.Context, uuid string) (Wishlist, error) {
	row := q.db.QueryRowContext(ctx, getWishlist, uuid)
	var i Wishlist
	err := row.Scan(
		&i.Uuid,
		&i.UserName,
		&i.Title,
		&i.Timestamp,
		&i.Access,
	)
	return i, err
}

const getWishlists = `-- name: GetWishlists :many
SELECT uuid, user_name, title, timestamp, access FROM wishlists
WHERE user_name = ?
ORDER BY timestamp
`

func (q *Queries) GetWishlists(ctx context.Context, userName string) ([]Wishlist, error) {
	rows, err := q.db.QueryContext(ctx, getWishlists, userName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Wishlist
	for rows.Next() {
		var i Wishlist
		if err := rows.Scan(
			&i.Uuid,
			&i.UserName,
			&i.Title,
			&i.Timestamp,
			&i.Access,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const setWishOrderIndex = `-- name: SetWishOrderIndex :exec
UPDATE wishes
SET order_index = ?
WHERE id = ?
`

type SetWishOrderIndexParams struct {
	OrderIndex int64
	ID         int64
}

func (q *Queries) SetWishOrderIndex(ctx context.Context, arg SetWishOrderIndexParams) error {
	_, err := q.db.ExecContext(ctx, setWishOrderIndex, arg.OrderIndex, arg.ID)
	return err
}

const setWishReserve = `-- name: SetWishReserve :exec
UPDATE wishes
SET reserved = ?
WHERE id = ?
`

type SetWishReserveParams struct {
	Reserved int64
	ID       int64
}

func (q *Queries) SetWishReserve(ctx context.Context, arg SetWishReserveParams) error {
	_, err := q.db.ExecContext(ctx, setWishReserve, arg.Reserved, arg.ID)
	return err
}

const updateLink = `-- name: UpdateLink :exec
UPDATE links
SET url = ?
WHERE wish_id = ? AND id = ?
`

type UpdateLinkParams struct {
	Url    string
	WishID int64
	ID     int64
}

func (q *Queries) UpdateLink(ctx context.Context, arg UpdateLinkParams) error {
	_, err := q.db.ExecContext(ctx, updateLink, arg.Url, arg.WishID, arg.ID)
	return err
}

const updatePassword = `-- name: UpdatePassword :exec
UPDATE users
SET passwordhash = ?
WHERE name = ?
`

type UpdatePasswordParams struct {
	Passwordhash []byte
	Name         string
}

func (q *Queries) UpdatePassword(ctx context.Context, arg UpdatePasswordParams) error {
	_, err := q.db.ExecContext(ctx, updatePassword, arg.Passwordhash, arg.Name)
	return err
}

const updateWish = `-- name: UpdateWish :exec
UPDATE wishes
SET name = ?,
    description = ?,
    image_url = ?,
    reserved = ?,
    active = ?,
    order_index = ?
WHERE id = ?
`

type UpdateWishParams struct {
	Name        string
	Description string
	ImageUrl    string
	Reserved    int64
	Active      int64
	OrderIndex  int64
	ID          int64
}

func (q *Queries) UpdateWish(ctx context.Context, arg UpdateWishParams) error {
	_, err := q.db.ExecContext(ctx, updateWish,
		arg.Name,
		arg.Description,
		arg.ImageUrl,
		arg.Reserved,
		arg.Active,
		arg.OrderIndex,
		arg.ID,
	)
	return err
}

const updateWishlist = `-- name: UpdateWishlist :exec
UPDATE wishlists
SET title = ?,
    access = ?
WHERE uuid = ?
`

type UpdateWishlistParams struct {
	Title  string
	Access int64
	Uuid   string
}

func (q *Queries) UpdateWishlist(ctx context.Context, arg UpdateWishlistParams) error {
	_, err := q.db.ExecContext(ctx, updateWishlist, arg.Title, arg.Access, arg.Uuid)
	return err
}
