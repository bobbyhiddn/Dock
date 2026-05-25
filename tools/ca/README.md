# Hermit Platform CA Tooling

Private Certificate Authority management for Shore-to-Dock mTLS authentication.

Each Shore instance authenticates to Dock using a client certificate signed by
this CA. The cert's Common Name (CN) becomes the Shore's identity on the network.

## Files

```
tools/ca/
├── ca.sh               — CA management script
├── .ca/
│   ├── ca.key          — CA private key (gitignored — keep secret!)
│   ├── ca.crt          — CA certificate (committed — public)
│   ├── index.txt       — issued cert index
│   ├── serial.txt      — next serial number
│   └── revoked.txt     — revoked serials (one per line)
└── certs/
    ├── shore-master/
    │   ├── shore-master.crt    — client cert for masternode
    │   └── shore-master.key    — private key (gitignored)
    └── shore-tower/
        ├── shore-tower.crt     — client cert for the-tower
        └── shore-tower.key     — private key (gitignored)
```

## Commands

### Initialize the CA (one-time)

```bash
./ca.sh init
```

Generates a 4096-bit RSA CA key and self-signed cert valid for 10 years.
Output goes to `.ca/` by default. The key is gitignored — back it up securely.
A future iteration will encrypt it with SOPS/age.

### Issue a cert for a Shore

```bash
./ca.sh issue --name shore-master
./ca.sh issue --name shore-tower

# Custom output directory (e.g., for deployment):
./ca.sh issue --name shore-master --out /etc/hermetic/certs/shore-master/
```

Generates a 2048-bit RSA key and a cert signed by the CA. CN = shore name.
Valid for 1 year. Private keys are gitignored.

### Revoke a Shore cert

```bash
./ca.sh revoke --name shore-tower
```

Adds the cert's serial to `.ca/revoked.txt` (one serial per line).
Dock reads this file on each Shore connection to reject revoked certs.

### List issued certs

```bash
./ca.sh list
```

Shows all issued certs from the index, including expiry and revocation status.

## mTLS Setup

### Dock side

Set the environment variable pointing to the CA cert:

```bash
DOCK_CA_CERT=/path/to/tools/ca/.ca/ca.crt
```

Dock loads this cert to validate incoming Shore WebSocket connections.
The Shore's CN from the cert becomes its registry identity.

### Shore side

Configure the `[dock]` section in `shore.toml`:

```toml
[dock]
enabled = true
url = "wss://hermit-dock.com/shore/connect"
name = "shore-master"
cert = "/etc/hermetic/certs/shore-master/shore-master.crt"
key  = "/etc/hermetic/certs/shore-master/shore-master.key"
ca   = "/etc/hermetic/certs/hermit-ca.crt"
services = ["rhode", "shell", "ordinal"]
heartbeat_interval = 15
reconnect_max = 60
```

Copy the CA cert to all Shore hosts:

```bash
scp tools/ca/.ca/ca.crt hermitos:/etc/hermetic/certs/hermit-ca.crt
scp tools/ca/certs/shore-master/shore-master.{crt,key} hermitos:/etc/hermetic/certs/shore-master/
```

## Security Notes

- **CA key** (`.ca/ca.key`) is gitignored. Back it up offline or encrypt with SOPS/age.
- **Shore private keys** (`certs/*/*.key`) are gitignored. Never commit them.
- **CA cert** (`.ca/ca.crt`) is safe to commit — it is the public trust anchor.
- **Shore certs** (`certs/*/*.crt`) are safe to commit — they are public.
- The revocation list (`.ca/revoked.txt`) is a simple text file. Dock reads it on each connection.
- Certs are valid for 1 year. Rotate before expiry with a new `ca.sh issue`.

## Issued Certs

| Shore | CN | Valid Until | Serial |
|---|---|---|---|
| masternode | shore-master | May 2027 | 1 |
| the-tower  | shore-tower  | May 2027 | 2 |
