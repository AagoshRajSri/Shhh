import { useState, useRef, useEffect } from 'react';
import { Send, Sun, Moon, ShieldAlert, FileText, Check, X, AlertTriangle } from 'lucide-react';
import { initDB, saveEncrypted } from './crypto/db';
import { signalService } from './crypto/signal';
import { wsService } from './network/ws';
import { encryptMediaChunked, decryptMediaChunked } from './crypto/media';
type Message = {
  id: string;
  sender: 'me' | 'them';
  content: string;
  timestamp: Date;
  type: 'text' | 'image' | 'audio' | 'document' | 'system' | 'file';
  size?: string;
  filename?: string;
  attachment?: {
    hash: string;
    keyHex: string;
    size: number;
    mimeType: string;
    url?: string;
  };
};

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [activeChat, setActiveChat] = useState<string | null>(null);
  const [inputValue, setInputValue] = useState('');
  const [messages, setMessages] = useState<Message[]>([]);
  const [lightMode, setLightMode] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [handle, setHandle] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [contacts, setContacts] = useState<string[]>([]);
  const [pendingRequests, setPendingRequests] = useState<{from: string, text: string}[]>([]);
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const [safetyNumber, setSafetyNumber] = useState<string | null>(null);
  const [keyChangeWarning, setKeyChangeWarning] = useState<{message: string, handle: string, pubkey: string} | null>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const [isInitializing, setIsInitializing] = useState(false);

  const handleLogin = async () => {
    let cleanHandle = handle.trim();
    if (!cleanHandle) {
      alert("Please enter a username.");
      return;
    }
    if (!cleanHandle.startsWith('#')) {
      cleanHandle = '#' + cleanHandle;
    }
    setHandle(cleanHandle);
    
    setIsInitializing(true);
    initDB();
    
    let identityBundle;
    const hasIdentity = await signalService.loadIdentity();
    if (!hasIdentity) {
      await signalService.generateIdentity();
      identityBundle = await signalService.generatePreKeyBundle();
    } else {
      identityBundle = await signalService.generatePreKeyBundle(); // Re-generate bundle for registration
    }
    
    let routingToken = null;

    try {
      if (!hasIdentity) {
        const response = await fetch('${API_URL}/api/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            handle: cleanHandle,
            identity_public_key: identityBundle.identityKey,
            signed_prekey: identityBundle.signedPreKey.publicKey,
            one_time_prekeys: identityBundle.preKeys.map((pk: any) => pk.publicKey),
            kyber_public_key: identityBundle.kyberPreKey
          })
        });
        
        if (response.status === 409) {
          throw new Error("Username already taken. Please choose a different username.");
        }

        if (!response.ok) {
          throw new Error(`Registration failed: ${response.status}`);
        }

        const data = await response.json();
        routingToken = data.routing_token;
      } else {
        // User already has a local identity. Lookup their own routing token.
        const res = await fetch(`${API_URL}/api/lookup/${encodeURIComponent(cleanHandle)}`);
        if (res.status === 429) {
          throw new Error("Too many requests. Please wait a moment.");
        }
        if (!res.ok) {
          throw new Error(`Failed to lookup existing user: ${res.status}`);
        }
        const data = await res.json();
        routingToken = data.routing_token;
      }

      if (routingToken) {
        wsService.connect(routingToken);
      }
    } catch (err: any) {
      console.warn("Backend error, falling back to mock routing token for dev", err);
      if (err.message && err.message.includes("already taken")) {
        alert(err.message + "\n\n(If this was your account but you cleared your browser data, your keys are lost and you must choose a new username).");
        setIsInitializing(false);
        return;
      }
      wsService.connect('my-mock-routing-token');
    }
    
    // Subscribe to incoming messages
    wsService.onMessage(async (encrypted_payload) => {
      console.log('Received sealed envelope from relay');
      
      // Sender identity is unknown until after decryption — pass null to verify
      // the cryptographic signature without enforcing a specific expected sender.
      const payload = await signalService.decryptMessage(null, encrypted_payload);
      
      if (payload.type === 'contact_request') {
        setPendingRequests(prev => {
          if (prev.some(r => r.from === payload.from)) return prev;
          return [...prev, { from: payload.from, text: payload.text }];
        });
      } else if (payload.type === 'message') {
        setContacts(prev => {
          if (!prev.includes(payload.from)) return [...prev, payload.from];
          return prev;
        });
        addMessage(payload.text, 'them');
      } else if (payload.type === 'attachment') {
        setContacts(prev => {
          if (!prev.includes(payload.from)) return [...prev, payload.from];
          return prev;
        });
        addMessage(payload.text, 'them', 'file', undefined, payload.text, payload.attachment);
      }
    });

    setIsInitializing(false);
    setIsLoggedIn(true);
  };

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputValue.trim()) return;

    setErrorMsg('');
    let targetHandle = activeChat;
    let messageText = inputValue.trim();
    
    if (!targetHandle) {
      const match = inputValue.match(/^#?([a-zA-Z0-9_-]{2,32})\s*(.*)$/);
      if (match) {
        targetHandle = '#' + match[1];
        messageText = match[2] || '';
        setInputValue(messageText);
      } else {
        setErrorMsg('Invalid format. Use: #username message');
        return;
      }
    } else {
      setInputValue('');
    }

    // 1. Username Regex Validation
    const regex = /^#[a-zA-Z0-9_-]{2,32}$/;
    if (!regex.test(targetHandle)) {
      setErrorMsg('Invalid username format. Must be 2-32 chars, starting with #, alphanumeric/dashes/underscores.');
      return;
    }

    // 2. Not Self
    if (targetHandle.toLowerCase() === handle.toLowerCase()) {
      setErrorMsg('You cannot send a message to yourself.');
      return;
    }

    // 3. Exists in Database & Get Routing Token
    try {
      const res = await fetch(`${API_URL}/api/lookup/${encodeURIComponent(targetHandle)}`);
      const data = await res.json();
      
      if (data.status !== 'success' || !data.routing_token) {
        setErrorMsg(`User ${targetHandle} does not exist in the database.`);
        return;
      }
      
      const to_routing_token = data.routing_token;

      if (await signalService.checkKeyChange(targetHandle, data.identity_pubkey)) {
        setKeyChangeWarning({
          message: `WARNING: The security keys for ${targetHandle} have changed! This could mean they re-registered, or it could be a man-in-the-middle attack. Verify safety numbers!`,
          handle: targetHandle,
          pubkey: data.identity_pubkey
        });
      }
      
      // 4. Contact Request vs Message
      const isContact = contacts.includes(targetHandle);
      const msgType = isContact ? 'message' : 'contact_request';
      
      if (!messageText && msgType === 'message') return;

      const payload = {
        from: handle,
        type: msgType,
        text: messageText
      };

      const encrypted_payload = await signalService.encryptMessage(targetHandle, data.identity_pubkey, payload);
      
      if (msgType === 'message') {
        addMessage(messageText, 'me');
      } else {
        addMessage(`Contact request sent to ${targetHandle}: "${messageText}"`, 'me', 'system');
      }

      console.log(`Routing sealed envelope to ${to_routing_token}`);
      wsService.send({
        to_routing_token,
        encrypted_payload
      });
      
      setActiveChat(targetHandle);
      
    } catch {
      console.warn('Backend not running, falling back to local routing for UI testing');
      
      const isContact = contacts.includes(targetHandle);
      const msgType = isContact ? 'message' : 'contact_request';
      if (!messageText && msgType === 'message') return;

      const payload = { from: handle, type: msgType, text: messageText };
      const encrypted_payload = await signalService.encryptMessage(targetHandle, 'fake_pubkey', payload);
      
      if (msgType === 'message') addMessage(messageText, 'me');
      else addMessage(`Contact request sent to ${targetHandle}: "${messageText}"`, 'me', 'system');

      wsService.send({ to_routing_token: 'my-mock-routing-token', encrypted_payload });
      setActiveChat(targetHandle);
      
      // Simulate recipient echoing back the contact request in offline mode
      setTimeout(async () => {
        const replyPayload = { from: targetHandle, type: msgType, text: messageText };
        const mockReplyCipher = await signalService.encryptMessage(handle, 'fake_pubkey', replyPayload);
        wsService.send({ to_routing_token: 'my-mock-routing-token', encrypted_payload: mockReplyCipher });
      }, 500);
    }
  };

  const uploadAndSendFile = async (file: File) => {
    if (!activeChat) return;
    setIsUploading(true);
    try {
      // 1. Client-side Convergent Encryption (ChaCha20-Poly1305)
      const { chunks, key, contentHash } = await encryptMediaChunked(file);
      const keyHex = Array.from(key).map(b => b.toString(16).padStart(2, '0')).join('');
      
      // 2. Initialize S3 Multipart Upload
      const initRes = await fetch('${API_URL}/api/upload/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash: contentHash, parts: chunks.length })
      });
      const initData = await initRes.json();
      
      if (initData.status === 'uploading' && initData.urls) {
        // Upload each chunk to its presigned URL
        const etags = [];
        for (let i = 0; i < chunks.length; i++) {
          const uploadRes = await fetch(initData.urls[i], {
            method: 'PUT',
            body: chunks[i]
          });
          const etag = uploadRes.headers.get('ETag');
          etags.push(etag?.replace(/"/g, '') || '');
        }
        
        // Complete the multipart upload
        await fetch('${API_URL}/api/upload/complete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ hash: contentHash, upload_id: initData.upload_id, etags })
        });
      }
      
      // 3. Send encrypted message payload to peer
      const attachment = {
        hash: contentHash,
        keyHex,
        size: file.size,
        mimeType: file.type
      };
      
      const payload = {
        from: handle,
        type: 'attachment',
        text: file.name,
        attachment
      };
      
      const res = await fetch(`${API_URL}/api/lookup/${encodeURIComponent(activeChat)}`);
      const data = await res.json();
      if (data.status === 'success' && data.routing_token) {
        if (await signalService.checkKeyChange(activeChat, data.identity_pubkey)) {
          alert(`WARNING: The security keys for ${activeChat} have changed! This could mean they re-registered, or it could be a man-in-the-middle attack. Verify safety numbers!`);
        }
        const encrypted_payload = await signalService.encryptMessage(activeChat, data.identity_pubkey, payload);
        wsService.send({
          to_routing_token: data.routing_token,
          encrypted_payload
        });
      }
      
      // Add local message
      setMessages(prev => [...prev, {
        id: Math.random().toString(36).substring(7),
        content: file.name,
        sender: 'me',
        timestamp: new Date(),
        type: 'file',
        attachment
      }]);
      
    } catch (e) {
      console.error('Upload failed', e);
      alert('Upload failed: ' + e);
    } finally {
      setIsUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const acceptRequest = async (from: string) => {
    setContacts(prev => [...prev, from]);
    setPendingRequests(prev => prev.filter(req => req.from !== from));
    setActiveChat(from);
    addMessage(`Secured end-to-end encrypted channel with ${from}.`, 'me', 'system');

    // Notify sender that their request was accepted
    try {
      const res = await fetch(`${API_URL}/api/lookup/${encodeURIComponent(from)}`);
      const data = await res.json();
      if (data.status === 'success' && data.routing_token) {
        const payload = {
          from: handle,
          type: 'message',
          text: `Accepted your contact request. Encrypted channel opened!`
        };
        const encrypted_payload = await signalService.encryptMessage(from, data.identity_pubkey, payload);
        wsService.send({
          to_routing_token: data.routing_token,
          encrypted_payload
        });
      }
    } catch (e) {
      console.warn('Failed to send acceptance ack', e);
    }
  };
  
  const declineRequest = (from: string) => {
    setPendingRequests(prev => prev.filter(req => req.from !== from));
  };

  const addMessage = (content: string, sender: 'me' | 'them', type: Message['type'] = 'text', size?: string, filename?: string, attachment?: any) => {
    setMessages(prev => [...prev, {
      id: Math.random().toString(36).substring(7),
      content,
      sender,
      timestamp: new Date(),
      type,
      size,
      filename,
      attachment
    }]);
  };

  const handleDownload = async (msg: Message) => {
    if (!msg.attachment) return;
    try {
      const res = await fetch(`${API_URL}/api/download/${msg.attachment.hash}`);
      const data = await res.json();
      if (!data.url) throw new Error("No download URL returned");
      
      const blobRes = await fetch(data.url);
      const encryptedBlob = await blobRes.blob();
      
      const keyBytes = new Uint8Array(msg.attachment.keyHex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
      const decryptedBlob = await decryptMediaChunked(encryptedBlob, keyBytes, msg.attachment.mimeType);
      
      const url = URL.createObjectURL(decryptedBlob);
      const a = document.createElement('a');
      a.href = url;
      a.download = msg.content || 'secure_attachment';
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error("Download decryption failed:", e);
      alert("Decryption failed: " + e);
    }
  };

  const verifySafetyNumber = async () => {
    if (!activeChat) return;
    try {
      const res = await fetch(`${API_URL}/api/lookup/${encodeURIComponent(activeChat)}`);
      const data = await res.json();
      if (data.status === 'success' && data.identity_pubkey) {
        const sn = await signalService.computeSafetyNumber(data.identity_pubkey);
        setSafetyNumber(sn);
      } else {
        alert('Could not fetch keys to compute safety number.');
      }
    } catch (e) {
      console.error(e);
      alert('Failed to compute safety number.');
    }
  };

  if (!isLoggedIn) {
    return (
      <div className={`min-h-screen ${lightMode ? 'bg-white text-black' : 'bg-black text-[#e5e5e5]'} flex items-center justify-center transition-colors duration-300`}>
        <button 
          onClick={() => setLightMode(!lightMode)} 
          className="absolute top-4 right-4 p-2 opacity-50 hover:opacity-100 transition-opacity z-10"
        >
          {lightMode ? <Moon size={20} /> : <Sun size={20} />}
        </button>

        <div className="flex h-screen w-full">
            <div className="w-full hidden md:inline-block relative">
                <div className={`absolute inset-0 ${lightMode ? 'bg-black/5' : 'bg-black/60'} pointer-events-none z-10`} />
                <img className="h-full w-full object-cover" src="/login-banner.png" alt="leftSideImage" />
            </div>
        
            <div className={`w-full flex flex-col items-center justify-center ${lightMode ? 'bg-white' : 'bg-black'}`}>
        
                <form 
                  onSubmit={(e) => { e.preventDefault(); handleLogin(); }}
                  className="md:w-96 w-80 flex flex-col items-center justify-center"
                >
                    <div className="mb-4">
                        <ShieldAlert size={48} className={lightMode ? 'text-black' : 'text-zinc-500'} />
                    </div>
                    <h2 className={`text-4xl font-medium ${lightMode ? 'text-gray-900' : 'text-white'}`}>Secure Auth</h2>
                    <p className={`text-sm mt-3 ${lightMode ? 'text-gray-500' : 'text-zinc-400'}`}>Zero-knowledge end-to-end encrypted chat</p>
        
                    <div className={`flex items-center gap-4 w-full my-8`}>
                        <div className={`w-full h-px ${lightMode ? 'bg-gray-300' : 'bg-zinc-800'}`}></div>
                        <p className={`w-full text-nowrap text-xs font-mono tracking-widest uppercase ${lightMode ? 'text-gray-500' : 'text-zinc-500'}`}>Generate Keys</p>
                        <div className={`w-full h-px ${lightMode ? 'bg-gray-300' : 'bg-zinc-800'}`}></div>
                    </div>

                    <div className={`mb-6 p-4 rounded-xl border flex items-start gap-3 ${lightMode ? 'bg-red-50 border-red-200 text-red-800' : 'bg-red-950/30 border-red-900/50 text-red-200'}`}>
                        <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
                        <div className="text-xs leading-relaxed">
                            <strong>Permanent Data Loss Warning:</strong> There is no account recovery. If you lose this device or clear your browser data, your identity and all conversations will be permanently lost.
                        </div>
                    </div>
        
                    <div className={`flex items-center w-full bg-transparent border ${lightMode ? 'border-gray-300' : 'border-zinc-800'} h-12 rounded-full overflow-hidden pl-6 gap-2 focus-within:border-zinc-500 transition-colors`}>
                        <svg width="16" height="11" viewBox="0 0 16 11" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path fillRule="evenodd" clipRule="evenodd" d="M0 .55.571 0H15.43l.57.55v9.9l-.571.55H.57L0 10.45zm1.143 1.138V9.9h13.714V1.69l-6.503 4.8h-.697zM13.749 1.1H2.25L8 5.356z" fill={lightMode ? "#6B7280" : "#888"}/>
                        </svg>
                        <input value={handle} onChange={e => setHandle(e.target.value)} type="text" placeholder="Handle (e.g. #alice)" className={`bg-transparent ${lightMode ? 'text-gray-900 placeholder-gray-500' : 'text-zinc-200 placeholder-zinc-600'} outline-none text-sm w-full h-full`} required />                 
                    </div>
        
                    <div className={`flex items-center mt-4 w-full bg-transparent border ${lightMode ? 'border-gray-300' : 'border-zinc-800'} h-12 rounded-full overflow-hidden pl-6 gap-2 focus-within:border-zinc-500 transition-colors`}>
                        <svg width="13" height="17" viewBox="0 0 13 17" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M13 8.5c0-.938-.729-1.7-1.625-1.7h-.812V4.25C10.563 1.907 8.74 0 6.5 0S2.438 1.907 2.438 4.25V6.8h-.813C.729 6.8 0 7.562 0 8.5v6.8c0 .938.729 1.7 1.625-1.7h9.75c.896 0 1.625-.762 1.625-1.7zM4.063 4.25c0-1.406 1.093-2.55 2.437-2.55s2.438 1.144 2.438 2.55V6.8H4.061z" fill={lightMode ? "#6B7280" : "#888"}/>
                        </svg>
                        <input value={passphrase} onChange={e => setPassphrase(e.target.value)} type="password" placeholder="Passphrase (local key backup — future feature)" className={`bg-transparent ${lightMode ? 'text-gray-900 placeholder-gray-500' : 'text-zinc-200 placeholder-zinc-600'} outline-none text-sm w-full h-full`} />
                    </div>
        
                    <div className={`w-full flex items-center justify-between mt-6 ${lightMode ? 'text-gray-500' : 'text-zinc-500'}`}>
                        <div className="flex items-center gap-2">
                            <input className="h-4 w-4 accent-zinc-500 rounded bg-zinc-800 border-zinc-700" type="checkbox" id="checkbox" defaultChecked />
                            <label className="text-sm cursor-pointer" htmlFor="checkbox">Remember me locally</label>
                        </div>
                    </div>
        
                    <button 
                      type="submit" 
                      disabled={isInitializing}
                      className={`mt-8 w-full h-11 flex items-center justify-center rounded-full font-medium transition-all ${
                        lightMode 
                          ? 'bg-black text-white hover:bg-zinc-800' 
                          : 'bg-white text-black hover:bg-zinc-200'
                      } ${isInitializing ? 'opacity-50 cursor-wait' : ''}`}
                    >
                        {isInitializing ? 'Generating Secure Identity...' : 'Generate & Login'}
                    </button>
                    
                    <p className={`text-sm mt-6 ${lightMode ? 'text-gray-500' : 'text-zinc-500'}`}>
                        Keys never leave your device.
                    </p>
                </form>
            </div>
        </div>
      </div>
    );
  }

  return (
    <div className={`min-h-screen flex flex-col ${lightMode ? 'bg-white text-black' : 'bg-black text-[#e5e5e5]'} transition-colors duration-300 relative`}>
      {/* Stealth Obsidian Pill Request Pop-up */}
      {pendingRequests.length > 0 && (
        <div className="fixed top-6 right-6 z-50 flex flex-col gap-3 max-w-sm w-full pointer-events-auto animate-in slide-in-from-top-4 fade-in duration-500">
          {pendingRequests.map((req, i) => (
            <div 
              key={i} 
              className="relative overflow-hidden rounded-2xl p-4 obsidian-pill border border-[#1f1f1f] shadow-2xl transition-all duration-300"
            >
              {/* Monochromatic Phosphor Ember Indicator */}
              <div className="absolute top-4 right-4 flex items-center gap-2">
                <span className="text-[10px] text-zinc-500 font-mono uppercase tracking-widest">Incoming</span>
                <div className="w-1.5 h-1.5 rounded-full bg-zinc-300 obsidian-dot shadow-[0_0_8px_rgba(255,255,255,0.4)]" />
              </div>

              {/* Minimal Header */}
              <div className="flex items-center gap-2 mb-3 text-zinc-400">
                <ShieldAlert size={14} className="opacity-70" />
                <span className="text-[11px] font-mono uppercase tracking-wider">Encrypted Request</span>
              </div>

              {/* Sender Info */}
              <div className="mb-4">
                <h4 className="text-sm text-zinc-100 flex items-center gap-1.5">
                  <span className="font-mono text-zinc-200">{req.from}</span>
                </h4>
                <p className="mt-2 text-xs text-zinc-400 font-mono bg-black/60 border border-zinc-900 rounded-md p-3 backdrop-blur-md line-clamp-2">
                  "{req.text}"
                </p>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2 mt-1 pt-3 border-t border-zinc-900">
                <button
                  onClick={() => acceptRequest(req.from)}
                  className="flex-1 py-2 px-3 rounded-xl text-xs font-mono font-medium text-black bg-zinc-300 hover:bg-zinc-100 shadow-[0_0_10px_rgba(255,255,255,0.1)] transition-all transform active:scale-95 flex items-center justify-center gap-1.5 cursor-pointer"
                >
                  <Check size={14} />
                  Accept Connection
                </button>
                <button
                  onClick={() => declineRequest(req.from)}
                  className="py-2 px-3 rounded-xl text-xs font-mono font-medium text-zinc-400 hover:text-zinc-200 bg-transparent hover:bg-zinc-900/50 border border-zinc-800 hover:border-zinc-600 transition-all active:scale-95 flex items-center justify-center gap-1 cursor-pointer"
                >
                  <X size={14} />
                  Dismiss
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      <button 
        onClick={() => setLightMode(!lightMode)} 
        className="absolute top-4 right-4 p-2 opacity-30 hover:opacity-100 transition-opacity z-10"
      >
        {lightMode ? <Moon size={20} /> : <Sun size={20} />}
      </button>

      {safetyNumber && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className={`max-w-md w-full rounded-2xl p-6 ${lightMode ? 'bg-white text-black' : 'bg-[#121212] border border-[#2a2a2a] text-white'} shadow-2xl`}>
            <h3 className="text-lg font-medium mb-2 flex items-center gap-2">
              <ShieldAlert size={20} /> 
              Verify Safety Number
            </h3>
            <p className={`text-sm mb-6 ${lightMode ? 'text-gray-600' : 'text-gray-400'}`}>
              Compare this number with {activeChat} out-of-band to verify that your end-to-end encryption has not been intercepted by the server.
            </p>
            <div className={`font-mono text-center text-lg md:text-xl tracking-wider leading-relaxed p-4 rounded-xl ${lightMode ? 'bg-gray-100' : 'bg-black border border-[#333]'}`}>
              {safetyNumber}
            </div>
            <button
              onClick={() => setSafetyNumber(null)}
              className={`mt-6 w-full py-3 rounded-xl font-medium transition-colors ${lightMode ? 'bg-black text-white hover:bg-gray-800' : 'bg-white text-black hover:bg-gray-200'}`}
            >
              Close
            </button>
          </div>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col max-w-3xl w-full mx-auto relative pt-16">
        
        {/* Chat Messages */}
        <div className="flex-1 overflow-y-auto px-4 pb-32 space-y-6">

          {messages.map((msg, idx) => {
            const isMe = msg.sender === 'me';
            const showTime = idx === 0 || msg.timestamp.getTime() - messages[idx-1].timestamp.getTime() > 300000;
            
            return (
              <div key={msg.id} className={`flex flex-col ${isMe ? 'items-end' : 'items-start'} animate-in fade-in slide-in-from-bottom-2 duration-300`}>
                {showTime && (
                  <span className="text-[10px] opacity-30 mb-2 px-2 uppercase tracking-wider">
                    {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                )}
                <div className={`max-w-[85%] sm:max-w-[70%] px-4 py-2.5 rounded-2xl ${
                  msg.type === 'system' ? (lightMode ? 'bg-transparent text-gray-400 text-xs italic border border-dashed border-gray-300' : 'bg-transparent text-zinc-500 text-xs italic border border-dashed border-zinc-800') :
                  isMe 
                    ? (lightMode ? 'bg-zinc-100 text-black rounded-br-sm' : 'bg-zinc-900 text-white rounded-br-sm')
                    : (lightMode ? 'bg-zinc-50 text-black border border-zinc-200 rounded-bl-sm' : 'bg-transparent border border-zinc-800 text-zinc-300 rounded-bl-sm')
                }`}>
                  {(msg.type === 'text' || msg.type === 'system') && (
                    <p className="leading-relaxed font-normal text-[15px]">{msg.content}</p>
                  )}
                  {msg.type === 'file' && msg.attachment && (
                    <div 
                      className="flex items-center gap-3 cursor-pointer hover:opacity-80 transition-opacity"
                      onClick={() => handleDownload(msg)}
                    >
                      <FileText size={20} className="opacity-50" />
                      <div className="flex flex-col">
                        <span className="text-sm font-medium">{msg.content}</span>
                        <span className="text-xs opacity-50">
                          {(msg.attachment.size / 1024 / 1024).toFixed(2)} MB • Click to decrypt
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
          <div ref={messagesEndRef} />
        </div>

        {/* Input Area */}
        <div className={`absolute bottom-0 left-0 right-0 p-6 bg-gradient-to-t ${lightMode ? 'from-white via-white to-transparent' : 'from-black via-black to-transparent'}`}>
          <form onSubmit={handleSend} className="relative w-full group">
            {!activeChat && (
              <div className="absolute -top-8 left-1/2 -translate-x-1/2 text-xs opacity-40 font-mono tracking-widest uppercase">
                New Conversation
              </div>
            )}
            <div className={`flex items-center w-full rounded-2xl px-5 py-4 transition-all duration-300 ${
              lightMode 
                ? 'bg-zinc-50 border border-zinc-200 shadow-sm' 
                : `bg-zinc-900/50 border ${errorMsg ? 'border-red-900/50' : 'border-zinc-800/50'} focus-within:border-zinc-700 focus-within:bg-zinc-900 shadow-[0_0_15px_rgba(255,255,255,0.02)]`
            }`}>
              {activeChat && (
                <button 
                  type="button"
                  onClick={verifySafetyNumber}
                  className="mr-3 text-sm font-medium opacity-60 hover:opacity-100 transition-opacity shrink-0 flex items-center gap-1 cursor-pointer"
                  title="Verify Safety Number"
                >
                  <ShieldAlert size={14} />
                  {activeChat}
                </button>
              )}
              
              <input
                type="file"
                ref={fileInputRef}
                className="hidden"
                onChange={(e) => {
                  if (e.target.files && e.target.files.length > 0) {
                    uploadAndSendFile(e.target.files[0]);
                  }
                }}
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                disabled={!activeChat || isUploading}
                className="mr-3 shrink-0 p-2 text-zinc-500 hover:text-zinc-300 transition-colors"
                title="Attach secure file"
              >
                <FileText size={18} />
              </button>

              <input
                type="text"
                value={inputValue}
                onKeyDown={(e) => {
                  if (e.key === 'Backspace' && inputValue === '') {
                    setActiveChat(null);
                  }
                }}
                onChange={(e) => {
                  setInputValue(e.target.value);
                  setErrorMsg('');
                }}
                placeholder={activeChat ? "Message..." : "#handle message..."}
                className={`w-full bg-transparent outline-none border-none text-[15px] ${
                  errorMsg ? (lightMode ? 'text-red-500' : 'text-red-400') : ''
                } placeholder:opacity-30`}
                autoFocus
              />
              <button 
                type="submit" 
                disabled={!inputValue.trim()}
                className={`ml-3 shrink-0 p-2 rounded-full transition-all ${
                  inputValue.trim() 
                    ? (lightMode ? 'bg-black text-white hover:bg-zinc-800' : 'bg-white text-black hover:bg-zinc-200')
                    : 'opacity-20 cursor-not-allowed'
                }`}
              >
                <Send size={16} />
              </button>
            </div>
            {errorMsg && (
              <div className="absolute -bottom-6 left-5 text-xs text-red-500/70 font-medium">
                {errorMsg}
              </div>
            )}
          </form>
        </div>

      </div>

      {keyChangeWarning && (
        <div className="absolute inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className={`p-6 max-w-sm rounded-2xl shadow-2xl border ${lightMode ? 'bg-white border-red-200' : 'bg-neutral-900 border-red-900'}`}>
            <div className="flex items-center space-x-3 text-red-500 mb-4">
              <ShieldAlert className="w-8 h-8" />
              <h3 className="text-xl font-bold">Security Alert</h3>
            </div>
            <p className={`text-sm mb-6 ${lightMode ? 'text-neutral-700' : 'text-neutral-300'}`}>
              {keyChangeWarning.message}
            </p>
            <button 
              onClick={async () => {
                await saveEncrypted('knownKeys', { handle: keyChangeWarning.handle, keyB64: keyChangeWarning.pubkey }, keyChangeWarning.handle);
                setKeyChangeWarning(null);
              }}
              className="w-full py-3 rounded-lg font-bold transition-all bg-red-600 hover:bg-red-700 text-white"
            >
              I Understand
            </button>
          </div>
        </div>
      )}

    </div>
  );
}
