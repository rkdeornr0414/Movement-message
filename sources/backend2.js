const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { AptosClient, AptosAccount, HexString } = require('aptos');

const app = express();
const port = 3000;

app.use(bodyParser.json());

// MongoDB setup
mongoose.connect('mongodb://localhost:27017/messenger', { useNewUrlParser: true, useUnifiedTopology: true });

// User schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
    address: { type: String, required: true, unique: true }
});

const User = mongoose.model('User', userSchema);

// Aptos Client
const client = new AptosClient('https://aptos.testnet.suzuka.movementlabs.xyz/v1/');

app.post('/register', async (req, res) => {
    const { username, password, address } = req.body;

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ address });
        if (existingUser) {
            return res.status(400).send({ error: 'User already registered.' });
        }

        // Encrypt password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save user in the database
        const newUser = new User({ username, password: hashedPassword, address });
        await newUser.save();

        // Register on the blockchain
        const privateKey = 'YOUR_PRIVATE_KEY';
        const account = new AptosAccount(HexString.ensure(privateKey).toUint8Array());

        const payload = {
            type: "entry_function_payload",
            function: "move_security_test::user_registration::register_user",
            arguments: [username],
            type_arguments: []
        };

        const transaction = await client.generateTransaction(account.address(), payload);
        const signedTxn = await client.signTransaction(account, transaction);
        const transactionRes = await client.submitTransaction(signedTxn);
        await client.waitForTransaction(transactionRes.hash);

        res.status(200).send({ success: true, address });
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});

app.post('/login', async (req, res) => {
    const { address, password } = req.body;

    try {
        // Find the user
        const user = await User.findOne({ address });
        if (!user) {
            return res.status(400).send({ error: 'User not found.' });
        }

        // Check the password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send({ error: 'Invalid credentials.' });
        }

        res.status(200).send({ success: true, username: user.username });
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});

// Message handling and other endpoints would go here

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
