
-- name: CreateUser :exec
INSERT INTO users (
    name, passwordhash
) VALUES(
    ?, ?
);

-- name: UpdatePassword :exec
UPDATE users
SET passwordhash = ?
WHERE name = ?;

-- name: GetUser :one
SELECT * FROM users
WHERE name = ? LIMIT 1;

-- name: GetUsers :many
SELECT * FROM users;

-- name: DeleteUser :exec
DELETE FROM users
WHERE name = ?;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: CreateWishlist :exec
INSERT INTO wishlists (
    uuid, user_name, title
) VALUES (
    ?, ?, ?
);

-- name: GetWishlist :one
SELECT * FROM wishlists
WHERE uuid = ? LIMIT 1;

-- name: GetWishlists :many
SELECT * FROM wishlists
WHERE user_name = ?;

-- name: UpdateWishlist :exec
UPDATE wishlists
SET title = ?
WHERE uuid = ?;

-- name: DeleteWishlist :exec
DELETE FROM wishlists
WHERE uuid = ?;

-- name: DeleteAllWishlists :exec
DELETE FROM wishlists
WHERE user_name = ?;

-- name: CreateWish :one
INSERT INTO wishes(
    wishlist_uuid, name, description, image_url, reserved
) VALUES (
    ?, ?, ?, ?, ?
)
RETURNING *;

-- name: GetWish :one
SELECT * FROM wishes
WHERE id = ? LIMIT 1;

-- name: GetWishes :many
SELECT * FROM wishes
WHERE wishlist_uuid = ?
ORDER BY id;

-- name: UpdateWish :exec
UPDATE wishes
SET name = ?,
    description = ?,
    image_url = ?,
    reserved = ?
WHERE id = ?;

-- name: SetWishReserve :exec
UPDATE wishes
SET reserved = ?
WHERE id = ?;

-- name: DeleteWish :exec
DELETE FROM wishes
WHERE id = ?;

-- name: DeleteAllWishes :exec
DELETE FROM wishes
WHERE wishlist_uuid = ?;

-- name: CreateLink :one
INSERT INTO links (
    wish_id, url
)
VALUES (
    ?, ?
)
RETURNING *;

-- name: GetLink :one
SELECT * FROM links
WHERE wish_id = ? AND id = ? LIMIT 1;

-- name: GetLinks :many
SELECT * FROM links
WHERE wish_id = ?
ORDER BY id;

-- name: UpdateLink :exec
UPDATE links
SET url = ?
WHERE wish_id = ? AND id = ?;

-- name: DeleteLink :exec
DELETE FROM links
WHERE wish_id = ? AND id = ?;

-- name: DeleteWishLinks :exec
DELETE FROM links
WHERE wish_id = ?;

-- name: DeleteAllLinks :exec
DELETE FROM links;
