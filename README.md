# Pal Whitelist Enforcer

A simple Go-based enforcer for Palworld Servers that automatically manages player access based on a whitelist. It interacts with the Palworld Server REST API to ensure only authorized players can stay on your server.

## Features

- **Automated Whitelisting**: Periodically checks connected players against a whitelist.
- **Configurable Actions**: Choose what happens to non-whitelisted players:
    - `kick`: Kicks the player from the server.
    - `ban`: Bans the player from the server.
    - `pending`: Bans the player and adds them to a pending list for review.
- **Management API**: Built-in REST API to check the enforcer status, view pending players, and permit new users.
- **Persistent Storage**: Saves whitelist and pending lists to simple text files.
- **Auto-Whitelisting**: Automatically adds the first few players to the whitelist if it's empty or below a configured threshold.

## Note on Compatibility

This tool is currently designed and tested to work with the Steam Palworld Dedicated Server on Windows. It has not been tested in other environments (e.g., Linux, Steam CMD).

## Getting Started

### Prerequisites

- Go 1.23 or higher.
- A Palworld Server with the REST API enabled.

### Installation

1. Clone the repository or download the source code.
2. Install dependencies:
   ```bash
   go mod download
   ```
3. Build the application:
   ```bash
   go build -o pal_whitelist_enforcer main.go
   ```

### Configuration

Create a `config.ini` file in the project root with the following structure:

```ini
[server]
host = 127.0.0.1
port = 8212
username = admin
password = your_pal_server_password
check_interval = 5s

[enforcer]
port = 8080
whitelist_file = whitelist.txt
pending_file = pending.txt
non_whitelist_action = pending
min_autowhitelist_user = 1
kick_message = you are not whitelisted
ban_message = request access to your friend or owner
```

#### Configuration Options

- **[server]**
    - `host`: The IP address of your Palworld Server.
    - `port`: The REST API port of your Palworld Server (default: 8212).
    - `username`: REST API username (default: admin).
    - `password`: REST API password.
    - `check_interval`: How often to check for unauthorized players (e.g., `5s`, `1m`).
- **[enforcer]**
    - `port`: The port where the Enforcer's own management API will listen.
    - `whitelist_file`: Path to the file containing whitelisted Steam/User IDs.
    - `pending_file`: Path to the file where unauthorized players are logged.
    - `non_whitelist_action`: Action to take (`kick`, `ban`, or `pending`).
    - `min_autowhitelist_user`: Minimum number of whitelisted users to automatically fill from joining players (useful for initial setup).
    - `kick_message`: Message displayed to players when they are kicked.
    - `ban_message`: Message displayed to players when they are banned.

## Management API

The enforcer provides a simple API for integration with other tools (like Discord bots or web panels).

### `GET /v1/api/info`
Returns the status and uptime of the enforcer.

### `GET /v1/api/pending/`
Returns a JSON list of User IDs that are currently in the pending list.

### `GET /v1/api/whitelist/`
Returns a JSON list of User IDs that are currently in the whitelist.

### `POST /v1/api/permit/`
Adds a user to the whitelist.
**Body:**
```json
{
  "userid": "steam_..."
}
```

## Files

- `whitelist.txt`: Contains one User ID per line. These users are allowed to play.
- `pending.txt`: Contains one User ID per line of players who were caught without being whitelisted.
- `main.go`: The main application logic.

## License

MIT
