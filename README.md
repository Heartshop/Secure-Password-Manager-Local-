# Secure Password Manager (local)

Local CLI password manager implemented in Java + SQLite.

Overview

- A minimal, local-first password manager that encrypts entries with a master password and stores
  ciphertext in a local SQLite database.

Features

- Master password key derivation (PBKDF2WithHmacSHA256)
- Per-entry encryption using AES-GCM
- Store encrypted entries in a local SQLite DB (`passwords.db`)
- CLI-first design; can be extended to a desktop UI (JavaFX) or other frontends

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
- This is a minimal example  audit, harden, and add secure backup for production use.

Contributing

- Suggestions, issues and PRs are welcome. If you plan to extend the project with a GUI,
  consider adding integration tests and documenting the threat model.

License

- (Add a license file or choose a license for your project.)
