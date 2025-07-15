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

    async function hybridEncryptPayload(jsonString) {
    // Generate AES key
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

    // Export raw AES key
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
      true, // extractable so we can export it
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
      true,  // extractable so we can export raw later
      ['decrypt']
    );
  }


  async function importPublicKey(pem) {
  return crypto.subtle.importKey(
    "spki",
    pemToBuffer(pem),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
}

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
    return null; // No signature to verify
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

async function encryptMessage(username, message) {
  const res = await fetch(`/get_key/${encodeURIComponent(username)}`);
  if (!res.ok) throw new Error("Failed to fetch public key");
  const { public_key } = await res.json();
  const pub = await importPublicKey(public_key);
  const aes = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aes,
    new TextEncoder().encode(message)
  );
  const raw = await crypto.subtle.exportKey("raw", aes);
  const encKey = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    pub,
    raw
  );
  return {
    encrypted_aes_key: btoa(
      String.fromCharCode(...new Uint8Array(encKey))
    ),
    iv: btoa(String.fromCharCode(...iv)),
    encrypted_data: btoa(String.fromCharCode(...new Uint8Array(ct))),
  };
}


async function decryptMessage(encrypted, privKey) {
  const ek = Uint8Array.from(atob(encrypted.encrypted_aes_key), (c) =>
    c.charCodeAt(0)
  );
  const iv = Uint8Array.from(atob(encrypted.iv), (c) => c.charCodeAt(0));
  const data = Uint8Array.from(atob(encrypted.encrypted_data), (c) =>
    c.charCodeAt(0)
  );
  const rawAes = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privKey,
    ek
  );
  const aesKey = await crypto.subtle.importKey(
    "raw",
    rawAes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKey,
    data
  );
  return new TextDecoder().decode(pt);
}


