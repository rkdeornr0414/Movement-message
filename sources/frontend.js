import React, { useState } from 'react';
import axios from 'axios';

function App() {
    const [recipient, setRecipient] = useState('');
    const [content, setContent] = useState('');
    const [owner, setOwner] = useState('');
    const [messages, setMessages] = useState([]);

    const sendMessage = async () => {
        try {
            const response = await axios.post('http://localhost:3000/send_message', {
                recipient,
                content,
                timestamp: Date.now()
            });
            alert('Message sent successfully. Transaction hash: ' + response.data.hash);
        } catch (error) {
            alert('Error sending message: ' + error.response.data.error);
        }
    };

    const getReceivedMessages = async () => {
        try {
            const response = await axios.get('http://localhost:3000/received_messages', {
                params: { owner }
            });
            setMessages(response.data.messages);
        } catch (error) {
            alert('Error fetching messages: ' + error.response.data.error);
        }
    };

    return (
        <div style={{ padding: 20 }}>
            <h2>Send Message</h2>
            <div>
                <input
                    type="text"
                    placeholder="Recipient Address"
                    value={recipient}
                    onChange={(e) => setRecipient(e.target.value)}
                    style={{ marginRight: 10 }}
                />
                <input
                    type="text"
                    placeholder="Message Content"
                    value={content}
                    onChange={(e) => setContent(e.target.value)}
                    style={{ marginRight: 10 }}
                />
                <button onClick={sendMessage}>Send Message</button>
            </div>

            <h2>Received Messages</h2>
            <div>
                <input
                    type="text"
                    placeholder="Your Address"
                    value={owner}
                    onChange={(e) => setOwner(e.target.value)}
                    style={{ marginRight: 10 }}
                />
                <button onClick={getReceivedMessages}>Get Messages</button>
            </div>

            <div>
                {messages.length > 0 ? (
                    <ul>
                        {messages.map((message, index) => (
                            <li key={index}>
                                <p><strong>Sender:</strong> {message.sender}</p>
                                <p><strong>Content:</strong> {message.content}</p>
                                <p><strong>Timestamp:</strong> {new Date(message.timestamp).toLocaleString()}</p>
                            </li>
                        ))}
                    </ul>
                ) : (
                    <p>No messages found.</p>
                )}
            </div>
        </div>
    );
}

export default App;
