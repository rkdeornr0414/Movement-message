# Movement Message

## Introduction

**Movement Message** is a decentralized messaging application built on the Aptos blockchain. It allows users to register, log in, and chat securely with real-time message updates. This project leverages blockchain technology for enhanced security and privacy, ensuring all user communications are safe and transparent.

## Installation

To run this project locally, follow these steps:

1. **Clone the repository:**

    ```bash
    git clone https://github.com/yourusername/movement-message.git
    cd movement-message
    ```

2. **Install dependencies for the client:**

    ```bash
    cd client
    npm install
    ```

3. **Install dependencies for the backend:**

    ```bash
    cd source
    npm install
    ```

4. **Set up the SQLite database:**

    Make sure you have SQLite installed. You can initialize the database with the required tables using the following commands:

    ```bash
    sqlite3 messenger.db
    .read init.sql
    .exit
    ```

5. **Start the backend server:**

    ```bash
    you need to put your private key in .env file
    node backend.js
    ```

6. **Start the client:**

    ```bash
    cd ./client/src/
    npm start
    ```

Your application should now be running on `http://localhost:3000`.

## Wallet Integration

**Important Note**: The Movement Message app currently supports wallet integration exclusively through Google Chrome. To connect your wallet, please ensure you are using Google Chrome and have the Petra wallet extension installed.

To connect your wallet:

1. Open the application in Google Chrome.
2. Ensure the Petra wallet extension is installed and configured.
3. Click on "Connect Wallet" and follow the instructions provided by the Petra wallet extension.

"Note: Currently, the Movement Message application only supports wallet integration via Google account login. To connect your wallet, please ensure you use a Google account and follow the instructions provided by the aptos wallet extension in Google Chrome."

## Features

- **Decentralized Chat**: Powered by the Aptos blockchain for secure, on-chain messaging.
- **Real-time Messaging**: Uses WebSocket for instant message delivery.
- **Wallet Authentication**: Ensures secure login and registration via wallet integration.
- **1:1 Chat Room**: Private, direct messaging between users.

## Technologies Used

- **Frontend**: React.js, TypeScript, CSS
- **Backend**: Node.js, Express, SQLite, WebSocket
- **Blockchain**: Aptos, Movement
