// backend.js
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const { AptosClient, AptosAccount, HexString } = require('aptos');
const http = require('http');
const WebSocket = require('ws');

const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(cors());

// Initialize SQLite Database
const db = new sqlite3.Database('./messenger.db');

// Create Users and Messages Table
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, address TEXT UNIQUE)");
    db.run("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, recipient TEXT, content TEXT, timestamp TEXT)");
});

// Initialize Aptos Client
const client = new AptosClient('https://aptos.testnet.suzuka.movementlabs.xyz/v1/');

// Create HTTP server for WebSocket
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

let sockets = [];

// WebSocket connection
wss.on('connection', (ws) => {
    sockets.push(ws);
    ws.on('message', (message) => {
        sockets.forEach((client) => {
            if (client !== ws && client.readyState === WebSocket.OPEN) {
                client.send(message);
            }
        });
    });

    ws.on('close', () => {
        sockets = sockets.filter((client) => client !== ws);
    });
});

// Register User Endpoint
app.post('/register', async (req, res) => {
    const { username, password, address } = req.body;

    db.get("SELECT * FROM users WHERE address = ?", [address], async (err, row) => {
        if (row) {
            return res.status(400).json({ error: 'User already registered.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        db.run("INSERT INTO users (username, password, address) VALUES (?, ?, ?)", [username, hashedPassword, address], (err) => {
            if (err) {
                return res.status(500).json({ error: 'Error saving user.' });
            }

            const privateKey = '';  // Replace with your actual private key
            const account = new AptosAccount(HexString.ensure(privateKey).toUint8Array());

            const payload = {
                type: "entry_function_payload",
                function: "move_security_test::user_messaging::register_user",
                arguments: [username],
                type_arguments: []
            };

            client.generateTransaction(account.address(), payload)
                .then(transaction => client.signTransaction(account, transaction))
                .then(signedTxn => client.submitTransaction(signedTxn))
                .then(transactionRes => client.waitForTransaction(transactionRes.hash))
                .then(() => res.status(200).json({ success: true, address }))
                .catch(error => res.status(500).json({ error: error.message }));
        });
    });
});

// Login Endpoint
app.post('/login', async (req, res) => {
    const { address, password } = req.body;

    db.get("SELECT * FROM users WHERE address = ?", [address], async (err, user) => {
        if (!user) {
            return res.status(400).json({ error: 'User not found.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid credentials.' });
        }

        res.status(200).json({ success: true, username: user.username });
    });
});

// Send Message Endpoint
app.post('/send_message', (req, res) => {
    const { sender, recipient, content, timestamp } = req.body;

    db.run("INSERT INTO messages (sender, recipient, content, timestamp) VALUES (?, ?, ?, ?)", [sender, recipient, content, timestamp], (err) => {
        if (err) {
            return res.status(500).json({ error: 'Error saving message.' });
        }
        // Notify all connected clients about the new message
        wss.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({ sender, recipient, content, timestamp }));
            }
        });
        res.status(200).json({ success: true });
    });
});

// Fetch Messages Endpoint
app.get('/messages', (req, res) => {
    const { address } = req.query;

    db.all("SELECT * FROM messages WHERE sender = ? OR recipient = ?", [address, address], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Error fetching messages.' });
        }
        res.status(200).json({ messages: rows });
    });
});

server.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
