import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Route, Routes, useNavigate, useLocation } from 'react-router-dom';
import axios from 'axios';
import './App.css'; // Custom CSS for styling

function Home() {
  const navigate = useNavigate();

  return (
    <div className="home">
      <button onClick={() => navigate('/login')}>Login</button>
      <button onClick={() => navigate('/register')}>Register</button>
    </div>
  );
}

function Register() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [address, setAddress] = useState('');

  const register = async () => {
    try {
      await axios.post('http://localhost:3000/register', { username, password, address });
      alert('User registered successfully!');
    } catch (error) {
      alert('Error registering user: ' + (error.response?.data.error || error.message));
    }
  };

  return (
    <div className="auth-container">
      <h2>Register</h2>
      <input type="text" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
      <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <input type="text" placeholder="Address" value={address} onChange={(e) => setAddress(e.target.value)} />
      <button onClick={register}>Register</button>
    </div>
  );
}

function Login() {
  const [address, setAddress] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();

  const login = async () => {
    try {
      const response = await axios.post('http://localhost:3000/login', { address, password });
      alert('Logged in as: ' + response.data.username);
      navigate('/chat', { state: { address } }); // Pass the address to the chat component
    } catch (error) {
      alert('Error logging in: ' + (error.response?.data.error || error.message));
    }
  };

  return (
    <div className="auth-container">
      <h2>Login</h2>
      <input type="text" placeholder="Address" value={address} onChange={(e) => setAddress(e.target.value)} />
      <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <button onClick={login}>Login</button>
    </div>
  );
}

function Chat() {
  const [recipient, setRecipient] = useState('');
  const [content, setContent] = useState('');
  const [messages, setMessages] = useState([]);
  const navigate = useNavigate();
  const location = useLocation();
  const senderAddress = location.state?.address; // Get sender's address from state

  useEffect(() => {
    const fetchMessages = async () => {
      try {
        const response = await axios.get('http://localhost:3000/messages', {
          params: { address: senderAddress }
        });
        setMessages(response.data.messages);
      } catch (error) {
        console.error('Error fetching messages:', error);
      }
    };

    fetchMessages();

    const ws = new WebSocket('ws://localhost:3000');
    ws.onmessage = (event) => {
      const newMessage = JSON.parse(event.data);
      if (newMessage.sender === senderAddress || newMessage.recipient === senderAddress) {
        setMessages((prevMessages) => [...prevMessages, newMessage]);
      }
    };

    return () => {
      ws.close();
    };
  }, [senderAddress]);

  const sendMessage = async () => {
    try {
      const timestamp = new Date().toISOString(); // Use ISO string for consistent timestamp format
      await axios.post('http://localhost:3000/send_message', { sender: senderAddress, recipient, content, timestamp });
      alert('Message sent successfully!');
      setMessages([...messages, { sender: senderAddress, recipient, content, timestamp }]);
    } catch (error) {
      alert('Error sending message: ' + (error.response?.data.error || error.message));
    }
  };

  const logout = () => {
    navigate('/');
  };

  return (
    <div className="chat-container">
      <h2>Messages</h2>
      <input type="text" placeholder="Recipient Address" value={recipient} onChange={(e) => setRecipient(e.target.value)} />
      <input type="text" placeholder="Message" value={content} onChange={(e) => setContent(e.target.value)} />
      <button onClick={sendMessage}>Send Message</button>

      <h3>Chat History</h3>
      <div className="chat-history">
        {messages.map((msg, index) => (
          <div key={index}>
            <strong>From:</strong> {msg.sender} <br />
            <strong>To:</strong> {msg.recipient} <br />
            <strong>Message:</strong> {msg.content} <br />
            <strong>Timestamp:</strong> {msg.timestamp}
          </div>
        ))}
      </div>
      <button onClick={logout} className="logout-button">Logout</button>
    </div>
  );
}

function App() {
  return (
    <Router>
      <div className="text-style text-top-left">Movement</div>
      <div className="text-style text-bottom-right">Message</div>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/register" element={<Register />} />
        <Route path="/login" element={<Login />} />
        <Route path="/chat" element={<Chat />} />
      </Routes>
    </Router>
  );
}

export default App;
