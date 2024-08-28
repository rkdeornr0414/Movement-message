const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { AptosClient, AptosAccount, HexString } = require('aptos');

const app = express();
const port = 3000;

app.use(bodyParser.json());

// Setup SQLite Database
const db = new sqlite3.Database('./messenger.db');

// Create Users Table
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, address TEXT UNIQUE)");
});

// Aptos Client
const client = new AptosClient('https://aptos.testnet.suzuka.movementlabs.xyz/v1/');

app.post('/register', async (req, res) => {
    const { username, password, address } = req.body;

    try {
        // Check if user already exists
        db.get("SELECT * FROM users WHERE address = ?", [address], async (err, row) => {
            if (row) {
                return res.status(400).send({ error: 'User already registered.' });
            }

            // Encrypt password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Save user in the database
            db.run("INSERT INTO users (username, password, address) VALUES (?, ?, ?)", [username, hashedPassword, address], function(err) {
                if (err) {
                    return res.status(500).send({ error: 'Error saving user.' });
                }

                // Register on the blockchain
                const privateKey = 'YOUR_PRIVATE_KEY';
                const account = new AptosAccount(HexString.ensure(privateKey).toUint8Array());

                const payload = {
                    type: "entry_function_payload",
                    function: "move_security_test::user_registration::register_user",
                    arguments: [username],
                    type_arguments: []
                };

                client.generateTransaction(account.address(), payload)
                    .then(transaction => client.signTransaction(account, transaction))
                    .then(signedTxn => client.submitTransaction(signedTxn))
                    .then(transactionRes => client.waitForTransaction(transactionRes.hash))
                    .then(() => res.status(200).send({ success: true, address }))
                    .catch(error => res.status(500).send({ error: error.message }));
            });
        });
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});

app.post('/login', async (req, res) => {
    const { address, password } = req.body;

    try {
        // Find the user
        db.get("SELECT * FROM users WHERE address = ?", [address], async (err, user) => {
            if (!user) {
                return res.status(400).send({ error: 'User not found.' });
            }

            // Check the password
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(400).send({ error: 'Invalid credentials.' });
            }

            res.status(200).send({ success: true, username: user.username });
        });
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
