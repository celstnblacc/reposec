// Vulnerable JavaScript code for testing

const express = require('express');
const fs = require('fs');
const path = require('path');

// JS-001: eval usage
function compute(expr) {
    return eval(expr);
}

// JS-002: path traversal without check
function readFile(userPath) {
    const filePath = path.join('/uploads', userPath);
    return fs.readFileSync(filePath);
}

// JS-003: symlink following
function listFiles(dir) {
    return fs.readdirSync(dir).map(f => path.join(dir, f));
}

// JS-004: prototype pollution
function deepMerge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object') {
            target[key] = deepMerge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// JS-006: XSS via innerHTML
function render(data) {
    document.getElementById('output').innerHTML = data;
}

// JS-008: console.log secrets
function auth(token) {
    console.log("Token received:", token);
}
