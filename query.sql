
-- name: CreateUser :exec
INSERT INTO users (
    name, passwordhash
) VALUES(
    ?, ?
);

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
DELETE FROM wishlists;

-- name: CreateWish :exec
INSERT INTO wishes(
    wishlist_uuid, wish_index, name, description, image_url, reserved
) VALUES (
    ?, ?, ?, ?, ?, ?
);

-- name: GetWish :one
SELECT * FROM wishes
WHERE wishlist_uuid = ? AND wish_index = ? LIMIT 1;

-- name: GetWishes :many
SELECT * FROM wishes
WHERE wishlist_uuid = ?
ORDER BY wish_index;

-- name: UpdateWish :exec
UPDATE wishes
SET name = ?,
    description = ?,
    image_url = ?,
    reserved = ?
WHERE wishlist_uuid = ? AND wish_index = ?;

-- name: SetWishReserve :exec
UPDATE wishes
SET reserved = ?
WHERE wishlist_uuid = ? AND wish_index = ?;

-- name: DeleteWish :exec
DELETE FROM wishes
WHERE wishlist_uuid = ? AND wish_index = ?;

-- name: DeleteAllWishes :exec
DELETE FROM wishes;

-- name: CreateLink :exec
INSERT INTO links (
    wish_id, link_index, url
)
VALUES (
    (SELECT id FROM wishes
     WHERE wishlist_uuid = ? AND wish_index = ?),
    ?,
    ?
)
RETURNING *;

-- name: GetLink :one
SELECT * FROM links
WHERE wish_id = (
    SELECT id FROM wishes WHERE wishlist_uuid = ? AND wish_index = ?
) AND link_index = ? LIMIT 1;

-- name: GetLinks :many
SELECT * FROM links
WHERE wish_id = (
    SELECT id FROM wishes WHERE wishlist_uuid = ? AND wish_index = ?
)
ORDER BY link_index;

-- name: GetUnusedLinks :many
SELECT * FROM links
WHERE wish_id = (
    SELECT id FROM wishes WHERE wishlist_uuid = ? AND wish_index = ?
) AND link_index >= ?
ORDER BY link_index;

-- name: UpdateLink :exec
UPDATE links
SET url = ?
WHERE wish_id = (
    SELECT id FROM wishes WHERE wishlist_uuid = ? AND wish_index = ?
) AND link_index = ?;

-- name: DeleteLink :exec
DELETE FROM links
WHERE wish_id = (
    SELECT id FROM wishes WHERE wishlist_uuid = ? AND wish_index = ?
) AND link_index = ?;

-- name: DeleteWishLinks :exec
DELETE FROM links
WHERE wish_id = (
    SELECT id FROM wishes WHERE wishlist_uuid = ? AND wish_index = ?
);

-- name: DeleteAllLinks :exec
DELETE FROM links;
