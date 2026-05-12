const express = require('express');
const cors = require('cors');
const { execFile } = require('child_process');
const path = require('path');
const os = require('os');

const app = express();
const fs = require('fs');

// Persistence Logic: Load keys from Env Variables if they exist
if (process.env.PRIVATE_KEY && process.env.PUBLIC_KEY) {
    try {
        fs.writeFileSync(path.join(__dirname, '..', 'private.pem'), process.env.PRIVATE_KEY);
        fs.writeFileSync(path.join(__dirname, '..', 'public.pem'), process.env.PUBLIC_KEY);
        console.log('Persistent Master Keys loaded from environment.');
    } catch (err) {
        console.error('Failed to write persistent keys:', err);
    }
}

app.use(cors());
app.use(express.json());

// Detect OS to use correct binary name
const isWindows = os.platform() === 'win32';
const BINARY_NAME = isWindows ? 'Encrypto.exe' : './Encrypto';
const EXECUTABLE_PATH = path.join(__dirname, '..', BINARY_NAME);
const ROOT_DIR = path.join(__dirname, '..');

app.post('/api/encrypt', (req, res) => {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'No message provided' });

    const b64message = Buffer.from(message, 'utf-8').toString('base64');

    execFile(EXECUTABLE_PATH, ['--encrypt', b64message], { cwd: ROOT_DIR }, (error, stdout, stderr) => {
        if (error) {
            console.error('Encryption Error:', stderr || error.message);
            return res.status(500).json({ error: 'Encryption failed' });
        }
        res.json({ payload: stdout.trim() });
    });
});

app.post('/api/decrypt', (req, res) => {
    const { payload } = req.body;
    if (!payload) return res.status(400).json({ error: 'No payload provided' });

    execFile(EXECUTABLE_PATH, ['--decrypt', payload], { cwd: ROOT_DIR }, (error, stdout, stderr) => {
        if (error) {
            console.error('Decryption Error:', stderr || error.message);
            return res.status(500).json({ error: 'Decryption failed. Ensure payload is correct.' });
        }
        
        const decryptedB64 = stdout.trim();
        const decryptedText = Buffer.from(decryptedB64, 'base64').toString('utf-8');
        
        res.json({ message: decryptedText });
    });
});

// Port for deployment (Render/Railway use the PORT env variable)
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Bridge server running on port ${PORT}`);
});
