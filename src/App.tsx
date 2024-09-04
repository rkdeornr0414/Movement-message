import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Route, Routes, useNavigate, useLocation } from 'react-router-dom';
import { WalletSelector } from "@aptos-labs/wallet-adapter-ant-design";
import { useWallet, WalletName } from '@aptos-labs/wallet-adapter-react';
import axios from 'axios';
import './App.css'; // Custom CSS for styling

function Home() {
  const navigate = useNavigate();
  const { connected, connect } = useWallet();

  const handleConnect = async () => {
    try {
      await connect("Petra" as WalletName); // Specify the wallet name explicitly
    } catch (err) {
      console.error("Error connecting wallet:", err);
    }
  };

  return (
    <div className="home">
      <WalletSelector />
      <button onClick={() => connected ? navigate('/login') : handleConnect()}>{connected ? 'Login' : 'Connect Wallet'}</button>
      <button onClick={() => connected ? navigate('/register') : handleConnect()}>{connected ? 'Register' : 'Connect Wallet'}</button>
    </div>
  );
}

function Register() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [address, setAddress] = useState('');
  const { connected, account } = useWallet();

  const register = async () => {
    if (!connected) {
      alert("Please connect your wallet to register.");
      return;
    }

    if (account?.address !== address) {
      alert("The connected wallet address does not match the provided address.");
      return;
    }

    try {
      await axios.post('http://localhost:3000/register', { username, password, address });
      alert('User registered successfully!');
    } catch (error: any) {
      if (error.response && error.response.data) {
        alert('Error registering user: ' + JSON.stringify(error.response.data));
      } else {
        alert('Error registering user: ' + error.message);
      }
    }
  };

  useEffect(() => {
    if (connected && account?.address) {
      setAddress(account.address);
    }
  }, [connected, account]);

  return (
    <div className="auth-container">
      <h2>Register</h2>
      <input type="text" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
      <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <input type="text" placeholder="Address" value={address} onChange={(e) => setAddress(e.target.value)} readOnly />
      <button onClick={register} disabled={!connected}>Register</button>
    </div>
  );
}

function Login() {
  const [address, setAddress] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();
  const { connected, account } = useWallet();

  const login = async () => {
    if (!connected) {
      alert("Please connect your wallet to log in.");
      return;
    }

    if (account?.address !== address) {
      alert("The connected wallet address does not match the provided address.");
      return;
    }

    try {
      const response = await axios.post('http://localhost:3000/login', { address, password });
      alert('Logged in as: ' + response.data.username);
      navigate('/chat', { state: { address } });
    } catch (error: any) {
      if (error.response && error.response.data) {
        alert('Error logging in: ' + JSON.stringify(error.response.data));
      } else {
        alert('Error logging in: ' + error.message);
      }
    }
  };

  useEffect(() => {
    if (connected && account?.address) {
      setAddress(account.address);
    }
  }, [connected, account]);

  return (
    <div className="auth-container">
      <h2>Login</h2>
      <input type="text" placeholder="Address" value={address} onChange={(e) => setAddress(e.target.value)} readOnly />
      <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <button onClick={login} disabled={!connected}>Login</button>
    </div>
  );
}

function Chat() {
  const [recipient, setRecipient] = useState('');
  const [content, setContent] = useState('');
  const [messages, setMessages] = useState<any[]>([]);
  const [selectedRecipient, setSelectedRecipient] = useState<string | null>(null);
  const [showNewMessage, setShowNewMessage] = useState(false); // State to toggle new message view
  const navigate = useNavigate();
  const location = useLocation();
  const senderAddress = location.state?.address;

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
      const timestamp = new Date().toISOString();
      await axios.post('http://localhost:3000/send_message', { sender: senderAddress, recipient, content, timestamp });
      alert('Message sent successfully!');
      setMessages([...messages, { sender: senderAddress, recipient, content, timestamp }]);
    } catch (error: any) {
      alert('Error sending message: ' + (error.response?.data.error || error.message));
    }
  };

  const logout = () => {
    navigate('/');
  };

  return (
    <div className="chat-page">
      {/* Contacts Sidebar */}
      <div className="chat-sidebar">
        <button className="toggle-button" onClick={() => document.querySelector('.contacts')?.classList.toggle('hidden')}>
          Contacts
        </button>
        <div className="contacts hidden">
          {Array.from(new Set(messages.map(msg => msg.sender === senderAddress ? msg.recipient : msg.sender))).map((contact, index) => (
            <div key={index} onClick={() => { setSelectedRecipient(contact); setRecipient(contact); setShowNewMessage(false); }} className={selectedRecipient === contact ? "selected" : ""}>
              {contact}
            </div>
          ))}
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="chat-container">
        <h2>Messages</h2>
        {showNewMessage && (
          <input type="text" placeholder="Recipient Address" value={recipient} onChange={(e) => setRecipient(e.target.value)} />
        )}
        <input type="text" placeholder="Message" value={content} onChange={(e) => setContent(e.target.value)} />
        <button onClick={sendMessage}>Send Message</button>
        <button onClick={() => setShowNewMessage(!showNewMessage)}>New Message</button>
        <button onClick={logout} className="logout-button">Logout</button>
      </div>

      {/* Chat History Sidebar */}
      <div className="chat-sidebar">
        <button className="toggle-button" onClick={() => document.querySelector('.chat-history')?.classList.toggle('hidden')}>
          Chat History
        </button>
        <div className="chat-history hidden">
          {messages.filter(msg => msg.sender === selectedRecipient || msg.recipient === selectedRecipient).map((msg, index) => (
            <div key={index}>
              <strong>From:</strong> {msg.sender} <br />
              <strong>To:</strong> {msg.recipient} <br />
              <strong>Message:</strong> {msg.content} <br />
              <strong>Timestamp:</strong> {msg.timestamp}
            </div>
          ))}
        </div>
      </div>
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
