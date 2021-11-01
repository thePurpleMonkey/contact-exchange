CREATE TABLE IF NOT EXISTS users
(
	user_id SERIAL PRIMARY KEY,
	email TEXT UNIQUE NOT NULL,
	password TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'VERIFY_EMAIL',
	verified TIMESTAMP WITH TIME ZONE,
	registered_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	last_login TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admins
(
	user_id INT PRIMARY KEY REFERENCES users(user_id),
	receive_new_user_emails BOOL DEFAULT TRUE,
	promoted_by INT NOT NULL REFERENCES users(user_id),
	promoted_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
	note TEXT
);

CREATE TABLE IF NOT EXISTS verification_emails
(
	user_id INT PRIMARY KEY REFERENCES users(user_id),
	token CHAR(64) NOT NULL,
	sent TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	expires TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP + interval '24 hours' NOT NULL
);

CREATE TABLE IF NOT EXISTS password_reset
(
	user_id INT PRIMARY KEY REFERENCES users(user_id),
	token CHAR(64) NOT NULL,
	sent TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
	expires TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP + interval '24 hours' NOT NULL
);

CREATE TABLE IF NOT EXISTS suspensions
(
	suspension_id SERIAL PRIMARY KEY,
	user_id INT NOT NULL REFERENCES users(user_id),
	start_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
	end_date TIMESTAMP WITH TIME ZONE,
	suspended_by INT REFERENCES users(user_id),
	ended_by INT REFERENCES users(user_id),
	reason TEXT
);

CREATE TABLE IF NOT EXISTS identity_verification
(
	user_id INT PRIMARY KEY REFERENCES users(user_id),
	name TEXT NOT NULL,
	email TEXT NOT NULL,
	postal TEXT NOT NULL,
	verified_by INT REFERENCES users(user_id),
	verified_date TIMESTAMP WITH TIME ZONE,
	note TEXT
);

CREATE TABLE IF NOT EXISTS profiles
(
	user_id INT PRIMARY KEY REFERENCES users(user_id),
	name TEXT,
	picture TEXT
);

CREATE TABLE IF NOT EXISTS contact_details
(
	contact_details_id SERIAL PRIMARY KEY,
	user_id INT REFERENCES users(user_id) NOT NULL,
	detail_name TEXT,
	detail_value TEXT,
	detail_type TEXT REFERENCES contact_detail_type(type_name),
	ORDER INT,
);

CREATE TABLE IF NOT EXISTS contact_detail_type
(
	type_name TEXT PRIMARY KEY NOT NULL,
);

INSERT INTO contact_detail_type (type_name)
VALUES 
	('text'),
	('multiline_text'),
	('email'),
	('phone')
ON CONFLICT DO NOTHING;

CREATE FUNCTION is_suspended(suspended_user int)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS
$$
BEGIN
	RETURN EXISTS(
		SELECT * 
		FROM suspensions
		WHERE user_id = suspended_user 
		  AND (end_date IS NULL OR end_date < CURRENT_TIMESTAMP)
	);
END;
$$;