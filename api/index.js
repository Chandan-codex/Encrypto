const express = require('express');
const cors = require('cors');
const { execFile } = require('child_process');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const EXECUTABLE_PATH = path.join(__dirname, '..', 'Encrypto.exe');
const ROOT_DIR = path.join(__dirname, '..');

app.post('/api/encrypt', (req, res) => {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'No message provided' });

    // Base64 encode the message before passing to C++ to avoid CLI encoding issues (emojis)
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
        
        // C++ returns the decrypted message as Base64 for safety; we decode it back to UTF-8
        const decryptedB64 = stdout.trim();
        const decryptedText = Buffer.from(decryptedB64, 'base64').toString('utf-8');
        
        res.json({ message: decryptedText });
    });
});

const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Bridge server running on http://localhost:${PORT}`);
});
