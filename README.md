# Reverse CAPTCHA Demo

This project demonstrates a bot-friendly CAPTCHA: the server streams rapid
arithmetic operations, and clients must submit the running total within a short
window.

## Run locally

```bash
npm install
npm start
```

Visit `http://localhost:3000`.

## How it works

- `/captcha/start` creates a short-lived challenge and returns the streaming URL.
- `/captcha/stream/:token` emits operations every 80 ms with 700 ms per-op windows.
- `/captcha/solve` validates the running total and timing constraints.

Tweak timings in `server.js` to make it more or less bot-friendly.
