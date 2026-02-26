// Safe JavaScript code for testing

const express = require('express');
const helmet = require('helmet');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(helmet());

// Safe: JSON.parse instead of eval
function compute(data) {
    return JSON.parse(data);
}

// Safe: path containment check
function readFile(userPath) {
    const baseDir = path.resolve('/uploads');
    const filePath = path.resolve(path.join('/uploads', userPath));
    if (!filePath.startsWith(baseDir)) {
        throw new Error('Path traversal detected');
    }
    return fs.readFileSync(filePath);
}

// Safe: textContent instead of innerHTML
function render(data) {
    document.getElementById('output').textContent = data;
}
