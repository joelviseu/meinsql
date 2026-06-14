# meinsql

Single-file PHP MySQL admin. Drop anywhere, works immediately.

## Concept

Minimal alternative to phpMyAdmin. One PHP file, zero dependencies, zero composer.

## Requirements

- **Single file** — everything in `index.php`
- **Credentials at top** — DB host/user/pass/db configured as PHP constants at the top of the file
- **Auth** — simple login form with username + password stored as constants; session-based (`$_SESSION`)
- **Layout** — two-column: left sidebar lists all tables (`SHOW TABLES`), right panel shows content
- **Table view** — click table name → `SELECT * FROM table` with pagination
- **Row actions** — edit (inline or form) and delete per row
- **Bootstrap** — responsive UI via Bootstrap CDN (no local assets)

## Out of scope

- No multi-DB support
- No import/export
- No schema editor (CREATE/ALTER/DROP)
- No user management
- No query console
