package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"text/template"
)

// Identity is a struct that models the structure of a Identity Verification request
type Identity struct {
	Email      string `json:"email"`
	Name       string `json:"name"`
	PostalCode string `json:"postal"`
}

// VerifyIdentityHandler handles verifying account and sending emails
func VerifyIdentityHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session")
	if err != nil {
		log.Printf("Verify identity handler - Unable to get session: %v\n", err)
		SendError(w, SERVER_ERROR_MESSAGE, http.StatusInternalServerError)
		return
	}

	if r.Method == "GET" {
		var token string = r.URL.Query().Get("token")

		if token == "" {
			SendError(w, `{"error": "No token provided."}`, http.StatusBadRequest)
			return
		}

		// Get user from database
		var userID int64
		if err := db.QueryRow("SELECT user_id FROM verification_emails WHERE token = $1", token).Scan(&userID); err != nil {
			if err == sql.ErrNoRows {
				log.Printf("Verify GET - Attempted to verify account with invalid token: %v\n", token)
				SendError(w, `{"error": "There was a problem verifying your account. Please try again."}`, http.StatusNotFound)
			} else {
				log.Printf("Verify GET - Unable to get verification record from database: %v\n", err)
				SendError(w, DATABASE_ERROR_MESSAGE, http.StatusInternalServerError)
			}
			return
		}

		// Check if the correct user is logged in
		if userID != session.Values["user_id"] {
			log.Printf("Verify GET - User %d logged in to verify account for %d.\n", session.Values["user_id"], userID)
			SendError(w, `{"error": "There was a problem verifying your account. Please try again."}`, http.StatusForbidden)
			return
		}

		// Start db transaction
		tx, err := db.Begin()
		if err != nil {
			log.Printf("Verify GET - Unable to begin database transaction: %v\n", err)
			SendError(w, DATABASE_ERROR_MESSAGE, http.StatusInternalServerError)
		}

		// Update the user in the database
		if _, err = tx.Exec("UPDATE users SET verified = CURRENT_TIMESTAMP, status = 'VERIFY_IDENTITY' WHERE user_id = $1", userID); err != nil {
			log.Printf("Verify GET - Unable to update user record in database: %v\n", err)
			SendError(w, DATABASE_ERROR_MESSAGE, http.StatusInternalServerError)
			return
		}

		// Delete the invite
		if _, err = tx.Exec("DELETE FROM verification_emails WHERE token = $1", token); err != nil {
			log.Printf("Verify GET - Unable to delete verification email record from database: %v\n", err)
			SendError(w, DATABASE_ERROR_MESSAGE, http.StatusInternalServerError)
			return
		}

		// Save changes
		if err = tx.Commit(); err != nil {
			log.Printf("Verify GET - Unable to commit database transaction: %v\n", err)
			SendError(w, DATABASE_ERROR_MESSAGE, http.StatusInternalServerError)
		}

		// Update session
		log.Printf("Verify GET - Verifying user %d's session.", session.Values["user_id"])
		session.Values["verified"] = true
		if err = session.Save(r, w); err != nil {
			log.Printf("Verify GET - Unable to save session state: %v\n", err)
			SendError(w, SERVER_ERROR_MESSAGE, http.StatusInternalServerError)
			return
		}

		log.Printf("Verify GET - User %d verified.\n", userID)
		w.WriteHeader(http.StatusOK)
		return
	} else if r.Method == "POST" {
		var userID int64 = session.Values["user_id"].(int64)
		log.Printf("Verify Identity POST - Adding identity verification for user %d\n", userID)

		// Parse and decode the request body into a new `Identity` instance
		identity := &Identity{}
		if err := json.NewDecoder(r.Body).Decode(identity); err != nil {
			// If there is something wrong with the request body, return a 400 status
			log.Printf("Verify Identity POST - Unable to decode request body: %v\n", err)
			body, _ := ioutil.ReadAll(r.Body)
			log.Printf("Body: %s\n", body)
			SendError(w, REQUEST_ERROR_MESSAGE, http.StatusBadRequest)
			return
		}

		// Create new identity verification record in database
		if _, err := db.Exec("INSERT INTO identity_verification (user_id, name, email, postal) VALUES ($1, $2, $3, $4)", userID, identity.Name, identity.Email, identity.PostalCode); err != nil {
			log.Printf("Verify Identity POST - Unable to insert identity verification record into database: %v\n", err)
			SendError(w, DATABASE_ERROR_MESSAGE, http.StatusInternalServerError)
			return
		}

		// Update account status
		if _, err := db.Exec("UPDATE users SET status = 'PENDING_APPROVAL' WHERE user_id = $1", userID); err != nil {
			log.Printf("Verify Identity POST - Unable to update user status in database: %v\n", err)
			SendError(w, DATABASE_ERROR_MESSAGE, http.StatusInternalServerError)
			return
		}

		go emailAdminsPendingApproval(identity.Name, identity.Email)

		w.WriteHeader(http.StatusOK)
	}
}

func emailAdminsPendingApproval(name, email string) {
	// Create email template
	htmlTemplate := template.Must(template.New("new_user_to_approve.html").ParseFiles("email_templates/new_user_to_approve.html", "html_fragments/site_name"))
	textTemplate := template.Must(template.New("new_user_to_approve.txt").ParseFiles("email_templates/new_user_to_approve.txt", "html_fragments/site_name"))

	var htmlBuffer, textBuffer bytes.Buffer
	url := "https://" + os.Getenv("HOST") + "/admin.html"
	data := struct {
		Href string
	}{url}

	if err := htmlTemplate.Execute(&htmlBuffer, data); err != nil {
		log.Printf("emailAdminsPendingApproval - Unable to execute html template: %v\n", err)
		return
	}
	if err := textTemplate.Execute(&textBuffer, data); err != nil {
		log.Printf("emailAdminsPendingApproval - Unable to execute text template: %v\n", err)
		return
	}

	// Get a list of all admins who are signed up for new user alerts
	rows, err := db.Query("SELECT email FROM admins NATURAL JOIN users WHERE receive_new_user_emails = true")
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("emailAdminsPendingApproval - There are no registered admins.")
		} else {
			log.Printf("emailAdminsPendingApproval - Unable to retrieve admin emails from database: %v\n", err)
		}
		return
	}
	defer rows.Close()

	// Retrieve rows from database
	var emails []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			log.Printf("emailAdminsPendingApproval - Unable to retrieve row from database result: %v\n", err)
		}
		emails = append(emails, email)
	}

	// Send emails to admins
	for _, email := range emails {
		if err := SendEmail(email, email, "New User to Verify", htmlBuffer.String(), textBuffer.String()); err != nil {
			log.Printf("emailAdminsPendingApproval - Failed to send verification email to %s: %v\n", email, err)
			return
		}
	}
}
