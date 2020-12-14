package storage

import (
	"database/sql"
	"log"
	"os"
)

func NewDatabase() (*sql.DB, error) {
	_, err := os.Stat("sqlite.storage")
	if os.IsNotExist(err) {
		file, err := os.Create("sqlite.storage")
		if err != nil {
			log.Fatal(err)
		}
		file.Close()
	}

	db, err := sql.Open("sqlite3", "sqlite.storage")
	if err != nil {
		log.Fatal(err)
	}

	createUsersTableSQL := `CREATE TABLE IF NOT EXISTS users (
		"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		"username" TEXT UNIQUE,
		"public_key" TEXT
	);`

	statement, err := db.Prepare(createUsersTableSQL)
	if err != nil {
		log.Fatal(err)
	}

	if _, err = statement.Exec(); err != nil {
		log.Fatal(err)
	}

	return db, nil
}

