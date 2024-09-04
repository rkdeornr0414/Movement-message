// src/index.tsx
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { PetraWallet } from "petra-plugin-wallet-adapter";
import { AptosWalletAdapterProvider } from "@aptos-labs/wallet-adapter-react";
import reportWebVitals from "./reportWebVitals";
import './index.css';

const wallets = [new PetraWallet()];

const root = ReactDOM.createRoot(
  document.getElementById("root") as HTMLElement
);
root.render(
  <React.StrictMode>
    <AptosWalletAdapterProvider plugins={wallets} autoConnect={true}>
      <App />
    </AptosWalletAdapterProvider>
  </React.StrictMode>
);

reportWebVitals();
