package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

// Contact is a struct that models the structure of a Contact, both in the request body, and in the DB
type Contact struct {
	UserID  int64            `json:"user_id"`
	Name    string           `json:"name"`
	Picture string           `json:"picture"`
	Details []ContactDetails `json:"details,omitempty"`
}

// ContactDetails represents all the optional data a user can fill out in their profile
type ContactDetails struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

// ContactsHandler handles GETting all songs and POSTing a new Contact
func ContactsHandler(w http.ResponseWriter, r *http.Request) {
	// session, err := store.Get(r, "session")
	// if err != nil {
	// 	log.Printf("Contacts handler - Unable to get session: %v\n", err)
	// 	SendError(w, SERVER_ERROR_MESSAGE, http.StatusInternalServerError)
	// 	return
	// }

	if r.Method == "GET" {
		// Retrieve songs in collection
		// rows, err := db.Query("SELECT song_id, name, date_added FROM songs WHERE collection_id = $1", collectionID)
		rows, err := db.Query("SELECT name, picture FROM profiles ORDER BY name")
		if err != nil {
			log.Printf("Contacts GET - Unable to get contacts from database: %v\n", err)
			SendError(w, DATABASE_ERROR_MESSAGE, http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		// Retrieve rows from database
		contacts := make([]Contact, 0)
		for rows.Next() {
			var Contact Contact
			if err := rows.Scan(&Contact.Name, &Contact.Picture); err != nil {
				log.Printf("Contacts GET - Unable to get contacts from database result: %v\n", err)
			}
			contacts = append(contacts, Contact)
		}

		// Check for errors from iterating over rows.
		if err := rows.Err(); err != nil {
			log.Printf("Contacts GET - Unable to get contacts from database result: %v\n", err)
			SendError(w, DATABASE_ERROR_MESSAGE, http.StatusInternalServerError)
			return
		}

		// Send response
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(contacts)
		return

	}
}

// ContactHandler handles retrieving a single contact
func ContactHandler(w http.ResponseWriter, r *http.Request) {
	// session, err := store.Get(r, "session")
	// if err != nil {
	// 	SendError(w, SERVER_ERROR_MESSAGE, http.StatusInternalServerError)
	// 	log.Printf("Contact handler - Unable to get session: %v\n", err)
	// 	return
	// }

	var contact Contact
	var err error
	// Get user ID from URL
	contact.UserID, err = strconv.ParseInt(mux.Vars(r)["user_id"], 10, 64)
	if err != nil {
		log.Printf("Contact handler - Unable to parse user id from URL: %v\n", err)
		SendError(w, URL_ERROR_MESSAGE, http.StatusBadRequest)
		return
	}

	if r.Method == "GET" {
		// Find the Contact in the database
		if err = db.QueryRow("SELECT name, picture FROM profiles WHERE profile.user_id = $1", contact.UserID).Scan(&contact.Name, &contact.Picture); err != nil {
			if err == sql.ErrNoRows {
				w.WriteHeader(http.StatusNotFound)
			} else {
				log.Printf("Contact GET - Unable to get contact %v from database: %v\n", contact.UserID, err)
				SendError(w, DATABASE_ERROR_MESSAGE, http.StatusInternalServerError)
			}
			return
		}

		// Retrieve songs in collection
		// rows, err := db.Query("SELECT song_id, name, date_added FROM songs WHERE collection_id = $1", collectionID)
		rows, err := db.Query("SELECT detail_name, detail_value, detail_type FROM contact_details WHERE user_id = $1 ORDER BY order", contact.UserID)
		if err != nil {
			log.Printf("Contact GET - Unable to get contact details from database: %v\n", err)
			SendError(w, DATABASE_ERROR_MESSAGE, http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		// Retrieve rows from database
		// contacts := make([]Contact, 0)
		for rows.Next() {
			var contactDetails ContactDetails
			if err := rows.Scan(&contactDetails.Name, &contactDetails.Value, &contactDetails.Type); err != nil {
				log.Printf("Contact GET - Unable to get contact details from database result: %v\n", err)
			}
			contact.Details = append(contact.Details, contactDetails)
		}

		// Check for errors from iterating over rows.
		if err := rows.Err(); err != nil {
			log.Printf("Contact GET - Unable to get songs from database result: %v\n", err)
			SendError(w, DATABASE_ERROR_MESSAGE, http.StatusInternalServerError)
			return
		}

		// Send response
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(contact)
		return
	} else if r.Method == "PUT" {
		// Save the URL collection ID so the user can't update another record
		// var collectionID = Contact.CollectionID

		// err := json.NewDecoder(r.Body).Decode(&Contact)
		// if err != nil {
		// 	// If there is something wrong with the request body, return a 400 status
		// 	log.Printf("Contact PUT - Unable to parse request body: %v\n", err)
		// 	body, _ := ioutil.ReadAll(r.Body)
		// 	log.Printf("Body: %s\n", body)
		// 	SendError(w, `{"error": "Unable to parse request."}`, http.StatusBadRequest)
		// 	return
		// }

		// // Update Contact in database
		// if *Contact.LastPerformed == "" {
		// 	Contact.LastPerformed = nil
		// }
		// if _, err = db.Exec("UPDATE songs SET artist = $1, location = $2, last_performed = $3, notes = $4, name = $5 WHERE collection_id = $6 AND song_id = $7", Contact.Artist, Contact.Location, Contact.LastPerformed, Contact.Notes, Contact.Name, collectionID, Contact.SongID); err != nil {
		// 	log.Printf("Contact PUT - Unable to update Contact in database: %v\n", err)
		// 	SendError(w, DATABASE_ERROR_MESSAGE, http.StatusInternalServerError)
		// 	return
		// }

		// w.WriteHeader(http.StatusOK)
		// return
	} else if r.Method == "DELETE" {
		// Start db transaction
		// 	tx, err := db.Begin()
		// 	if err != nil {
		// 		log.Printf("Contact DELETE - Unable to start database transaction: %v\n", err)
		// 		SendError(w, DATABASE_ERROR_MESSAGE, http.StatusInternalServerError)
		// 	}

		// 	// Removed Contact tags
		// 	if _, err = tx.Exec("DELETE FROM tagged_songs WHERE song_id = $1", Contact.SongID); err != nil {
		// 		log.Printf("Contact DELETE - Unable to remove Contact tags from database: %v\n", err)
		// 		SendError(w, DATABASE_ERROR_MESSAGE, http.StatusInternalServerError)
		// 		return
		// 	}

		// 	// Delete Contact
		// 	var result sql.Result
		// 	if result, err = tx.Exec("DELETE FROM songs WHERE collection_id = $1 AND song_id = $2", Contact.CollectionID, Contact.SongID); err != nil {
		// 		log.Printf("Contact DELETE - Unable to delete Contact from database: %v\n", err)
		// 		SendError(w, DATABASE_ERROR_MESSAGE, http.StatusInternalServerError)
		// 		return
		// 	}

		// 	// Check if a Contact was actually deleted
		// 	var rowsAffected int64
		// 	if rowsAffected, err = result.RowsAffected(); err != nil {
		// 		log.Printf("Contact DELETE - Unable to get rows affected. Assuming everything is fine? Error: %v\n", err)
		// 	} else if rowsAffected == 0 {
		// 		log.Printf("Contact DELETE - No rows were deleted from the database for Contact id %d\n", Contact.SongID)
		// 		SendError(w, `{"error": "No Contact was found with that ID"}`, http.StatusNotFound)
		// 		return
		// 	}

		// 	// Save changes
		// 	if err = tx.Commit(); err != nil {
		// 		log.Printf("Contact DELETE - Unable to commit database transaction: %v\n", err)
		// 		SendError(w, DATABASE_ERROR_MESSAGE, http.StatusInternalServerError)
		// 		return
		// 	}

		// 	log.Printf("Contact DELETE - User %d deleted Contact %d from collection %d.\n", session.Values["user_id"], Contact.SongID, Contact.CollectionID)
		// 	w.WriteHeader(http.StatusOK)
		// 	return
	}
}
