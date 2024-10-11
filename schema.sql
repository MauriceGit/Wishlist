CREATE TABLE IF NOT EXISTS users (
    name TEXT NOT NULL PRIMARY KEY,
    passwordhash BLOB
);

CREATE TABLE IF NOT EXISTS wishlists (
    uuid TEXT NOT NULL PRIMARY KEY,
    user_name TEXT NOT NULL,
    title TEXT NOT NULL,
    FOREIGN KEY (user_name) REFERENCES users(name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS wishes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wishlist_uuid TEXT NOT NULL,
    wish_index INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    image_url TEXT NOT NULL,
    reserved INTEGER NOT NULL,
    FOREIGN KEY (wishlist_uuid) REFERENCES wishlists(uuid) ON DELETE CASCADE,
    UNIQUE (wishlist_uuid, wish_index)
);

CREATE TABLE IF NOT EXISTS links (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    wish_id INTEGER NOT NULL,
    link_index INTEGER NOT NULL,
    url TEXT NOT NULL,
    FOREIGN KEY (wish_id) REFERENCES wishes(id) ON DELETE CASCADE,
    UNIQUE (wish_id, link_index)
);
