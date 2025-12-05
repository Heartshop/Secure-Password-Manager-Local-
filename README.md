# Password Manager (local)

Simple local password manager implemented in Java + SQLite.

Features:
- Master password derived key (PBKDF2WithHmacSHA256)
- AES-GCM encryption per entry
- Store encrypted entries in a local SQLite DB (`passwords.db`)

Quick start

1. Build (requires Maven):

```powershell
cd C:\Users\Jackc\Projects\password-manager
mvn package
```

2. Run (examples):

- Initialize DB:
```powershell
java -jar target\password-manager-0.1.0.jar init
```

- Add entry:
```powershell
java -jar target\password-manager-0.1.0.jar add "example.com" "alice" --note "My account"
```

- Get entry:
```powershell
java -jar target\password-manager-0.1.0.jar get "example.com"
```

- List entries:
```powershell
java -jar target\password-manager-0.1.0.jar list
```

Security notes
- Keep your master password secret. The app derives a key with PBKDF2 and stores a salt in the DB.
- This is a minimal example — audit, harden and add secure backup for production use.

