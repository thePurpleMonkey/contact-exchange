@echo off

echo Building...
cd ..
set /P SESSION_KEY=<secrets/key.txt
set /P SENDGRID_API_KEY=<SendGrid_API_key.txt
set HOST=localhost:8000
set CERT_FILE=C:\Users\mhump\.ssh\localhost.crt
set KEY_FILE=C:\Users\mhump\.ssh\localhost.key
set PORT=8000
set DB_USERNAME=contacts
set /P DB_PASSWORD=<secrets/db_password.txt
set ADMIN_EMAIL=contactexchange@michaelhumphrey.dev
go build -ldflags="-linkmode=internal -extld=none"
if /I "%ERRORLEVEL%" NEQ "0" (
	echo Build failed.
) ELSE (
	echo Running...
	contact-exchange.exe
)