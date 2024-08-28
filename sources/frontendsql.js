import React, { useState } from 'react';
import axios from 'axios';

function App() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [address, setAddress] = useState('');
    const [content, setContent] = useState('');
    const [recipient, setRecipient] = useState('');
    const [messages, setMessages] = useState([]);

    const register = async () => {
        try {
            const response = await axios.post('http://localhost:3000/register', {
                username,
                password,
                address
            });
            alert('User registered successfully!');
        } catch (error) {
            const errorMessage = error.response?.data?.error || error.message || 'Unknown error';
            alert('Error registering user: ' + errorMessage);
        }
    };

    const login = async () => {
        try {
            const response = await axios.post('http://localhost:3000/login', {
                address,
                password
            });
            alert('Logged in as: ' + response.data.username);
        } catch (error) {
            const errorMessage = error.response?.data?.error || error.message || 'Unknown error';
            alert('Error logging in: ' + errorMessage);
        }
    };

    // Additional functionality for sending and receiving messages

    return (
        <div style={{ padding: 20 }}>
            <h2>Register</h2>
            <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                style={{ marginRight: 10 }}
            />
            <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                style={{ marginRight: 10 }}
            />
            <input
                type="text"
                placeholder="Address"
                value={address}
                onChange={(e) => setAddress(e.target.value)}
                style={{ marginRight: 10 }}
            />
            <button onClick={register}>Register</button>

            <h2>Login</h2>
            <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                style={{ marginRight: 10 }}
            />
            <input
                type="text"
                placeholder="Address"
                value={address}
                onChange={(e) => setAddress(e.target.value)}
                style={{ marginRight: 10 }}
            />
            <button onClick={login}>Login</button>

            {/* Additional UI elements for messaging */}
        </div>
    );
}

export default App;
