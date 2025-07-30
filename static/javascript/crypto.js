// ——— Utility Functions ———
function pemToBuffer(pem) {
  const b64 = pem.replace(/-----(BEGIN|END)[^-]+-----|\s/g, "");
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
}

function arrayBufferToPem(buffer, label) {
  const bytes = new Uint8Array(buffer);
  const b64 = btoa(String.fromCharCode(...bytes));
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

function pemToArrayBuffer(pem) {
  return pemToBuffer(pem);
}

// ——— Hybrid Encryption ———

async function hybridEncryptPayload(jsonString) {
  const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt']
  );
  
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedData = new TextEncoder().encode(jsonString);
  
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    encodedData
  );

  
  const rawAesKey = await crypto.subtle.exportKey('raw', aesKey);

  // Fetch server RSA public key
  const serverPem = await fetch('/get_public_key').then(res => res.text());
  const serverPublicKey = await crypto.subtle.importKey(
    'spki',
    pemToArrayBuffer(serverPem),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  );

  // Encrypt AES key with server RSA public key
  const encryptedAesKey = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    serverPublicKey,
    rawAesKey
  );

  return {
    encrypted_aes_key: btoa(String.fromCharCode(...new Uint8Array(encryptedAesKey))),
    iv: btoa(String.fromCharCode(...iv)),
    encrypted_data: btoa(String.fromCharCode(...new Uint8Array(ciphertext)))
  };
}



async function encryptPrivateKey(privateKeyPem, password) {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(16));

  const passwordKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 600000,
      hash: 'SHA-512'
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const privateKeyBuffer = pemToArrayBuffer(privateKeyPem);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    privateKeyBuffer
  );

  return {
    version: 2,
    algorithm: 'AES-256-GCM',
    iterations: 600000,
    salt: btoa(String.fromCharCode(...salt)),
    iv: btoa(String.fromCharCode(...iv)),
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext)))
  };
}

async function decryptPrivateKey(encryptedData, password) {
  const salt = Uint8Array.from(atob(encryptedData.salt), c => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(encryptedData.iv), c => c.charCodeAt(0));
  const ciphertext = Uint8Array.from(atob(encryptedData.ciphertext), c => c.charCodeAt(0));

  const passwordKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: encryptedData.iterations,
      hash: 'SHA-512'
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    true, 
    ['decrypt']
  );

  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    ciphertext
  );

  return crypto.subtle.importKey(
    'pkcs8',
    decryptedBuffer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,  
    ['decrypt']
  );
}

// ——— Public Key Operations ———

async function importPublicKey(pem) {
  return crypto.subtle.importKey(
    "spki",
    pemToBuffer(pem),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
}

// ——— Digital Signatures ———

async function signMessage(message, privateKey) {
  const encoded = new TextEncoder().encode(message);
  const signature = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    privateKey,
    encoded
  );
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

async function verifySignature(message, signatureB64, publicKeyPem) {
  if (!signatureB64) {
    return null; 
  }
  
  try {
    const signature = Uint8Array.from(atob(signatureB64), (c) =>
      c.charCodeAt(0)
    );
    const data = new TextEncoder().encode(message);
    const keyBuffer = pemToBuffer(publicKeyPem);
    const pubKey = await crypto.subtle.importKey(
      "spki",
      keyBuffer,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );
    return await crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      pubKey,
      signature,
      data
    );
  } catch (err) {
    console.error("Signature verification failed:", err);
    return false;
  }
}

// ——— Message Encryption/Decryption ———

async function encryptMessage(recipientUsername, message) {

  const recipientRes = await fetch(`/get_key/${encodeURIComponent(recipientUsername)}`);
  if (!recipientRes.ok) throw new Error("Failed to fetch recipient's public key");
  
  const { public_key: recipientPublicKeyPem } = await recipientRes.json();
  const recipientPublicKey = await importPublicKey(recipientPublicKeyPem);
  
 
  const senderRes = await fetch(`/get_key/${encodeURIComponent(window.currentUser)}`);
  if (!senderRes.ok) throw new Error("Failed to fetch sender's public key");
  
  const { public_key: senderPublicKeyPem } = await senderRes.json();
  const senderPublicKey = await importPublicKey(senderPublicKeyPem);
  

  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"]
  );
  
S
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedMessage = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    new TextEncoder().encode(message)
  );
  

  const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
  

  const encryptedKeyForRecipient = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    recipientPublicKey,
    rawAesKey
  );
  

  const encryptedKeyForSender = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    senderPublicKey,
    rawAesKey
  );
  
  return {
    encrypted_message: btoa(String.fromCharCode(...new Uint8Array(encryptedMessage))),
    iv: btoa(String.fromCharCode(...iv)),
    encrypted_key_for_recipient: btoa(String.fromCharCode(...new Uint8Array(encryptedKeyForRecipient))),
    encrypted_key_for_sender: btoa(String.fromCharCode(...new Uint8Array(encryptedKeyForSender)))
  };
}


async function decryptMessage(encryptedData, currentUser, messageFromUser, messageToUser) {

  const isSender = currentUser === messageFromUser;
  const isRecipient = currentUser === messageToUser;
  
  if (!isSender && !isRecipient) {
    throw new Error("User is neither sender nor recipient of this message");
  }

  const encryptedAesKey = isSender 
    ? encryptedData.encrypted_key_for_sender 
    : encryptedData.encrypted_key_for_recipient;
  
  if (!encryptedAesKey) {
    throw new Error(`No encrypted key available for ${isSender ? 'sender' : 'recipient'}`);
  }
  

  const encryptedKeyBytes = Uint8Array.from(atob(encryptedAesKey), c => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(encryptedData.iv), c => c.charCodeAt(0));
  const encryptedMessageBytes = Uint8Array.from(atob(encryptedData.encrypted_message), c => c.charCodeAt(0));
  

  const rawAesKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    window.userPrivateKey,
    encryptedKeyBytes
  );

  const aesKey = await crypto.subtle.importKey(
    "raw",
    rawAesKey,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );
  

  const decryptedMessage = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encryptedMessageBytes
  );
  
  return new TextDecoder().decode(decryptedMessage);
}