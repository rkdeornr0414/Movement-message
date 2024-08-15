const express = require('express');
const bodyParser = require('body-parser');
const { AptosClient, AptosAccount, FaucetClient, HexString } = require('aptos');

const app = express();
const port = 3000;

app.use(bodyParser.json());

const client = new AptosClient('https://fullnode.devnet.aptoslabs.com/v1');
const faucetClient = new FaucetClient('https://faucet.devnet.aptoslabs.com');

const privateKey = ''; // 사용자 계정의 비밀키
const account = new AptosAccount(HexString.ensure(privateKey).toUint8Array());

// 메시지 전송 API
app.post('/send_message', async (req, res) => {
    const { recipient, content, timestamp } = req.body;

    const payload = {
        type: "entry_function_payload",
        function: "move_security_test::young_move::send_message",
        arguments: [
            recipient,
            HexString.ensure(content).toUint8Array(),
            timestamp
        ],
        type_arguments: []
    };

    try {
        const transaction = await client.generateTransaction(account.address(), payload);
        const signedTxn = await client.signTransaction(account, transaction);
        const transactionRes = await client.submitTransaction(signedTxn);
        await client.waitForTransaction(transactionRes.hash);
        res.status(200).send({ success: true, hash: transactionRes.hash });
    } catch (error) {
        res.status(500).send({ success: false, error: error.message });
    }
});

// 받은 메시지 조회 API
app.get('/received_messages', async (req, res) => {
    const { owner } = req.query;

    const payload = {
        function: "move_security_test::young_move::get_received_messages",
        arguments: [owner],
        type_arguments: [],
        type: "entry_function_payload"
    };

    try {
        const transaction = await client.generateTransaction(account.address(), payload);
        const signedTxn = await client.signTransaction(account, transaction);
        const transactionRes = await client.submitTransaction(signedTxn);
        await client.waitForTransaction(transactionRes.hash);

        const result = await client.getTransactionByHash(transactionRes.hash);
        res.status(200).send({ success: true, messages: result });
    } catch (error) {
        res.status(500).send({ success: false, error: error.message });
    }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
