# ScamShield Server

Backend API for **ScamShield**, a security-focused application for detecting potential scam, phishing, and malicious websites.

## Tech Stack

* Node.js
* Express.js
* TypeScript
* MongoDB
* Google Gemini AI
* Zod
* Axios
* Better Auth

## Features

* URL security analysis
* Scam detection
* Phishing detection
* AI-powered website analysis
* Company identification
* Website metadata extraction
* Trust score calculation
* MongoDB database integration
* Authentication
* Request validation
* Error handling
* REST API

## Project Structure

```text id="w6jz7e"
ScamShield-Server/
├── index.ts
├── gemini.ts
├── package.json
├── tsconfig.json
├── .env
├── .gitignore
└── ...
```

## Installation

```bash id="2p8s3a"
git clone https://github.com/topu9872-cpu/Scamshield-Server.git
cd ScamShield-Server
npm install
```

## Environment Variables

Create a `.env` file in the project root and configure the required environment variables for your local or production environment.

**Never commit `.env` files, API keys, database credentials, or authentication secrets to GitHub.**

## Development

```bash id="6j1q1r"
npm run dev
```

The development server runs on:

```text id="4i5lqk"
http://localhost:5000
```

## Production

Build the project:

```bash id="d5w9x0"
npm run build
```

Start the production server:

```bash id="j2j4pm"
npm start
```

## API Endpoints

### Company Details

```http id="3zj3ps"
GET /company-details?url=https://example.com
```

Returns company and website information including:

* Company name
* Domain
* Website title
* Website description
* Website image
* Trust score
* Scam status

### Security Scan

```http id="qv5m4f"
POST /scan
```

Analyzes supported inputs for potential security threats.

## Security Analysis

ScamShield evaluates multiple security signals, including:

* HTTPS status
* Website metadata
* Malicious indicators
* Suspicious indicators
* AI analysis

These signals are combined to calculate the ScamShield trust score.

## Database

ScamShield uses **MongoDB** for storing application data.

## Security Practices

Never commit sensitive information such as:

```text id="k4l0f7"
.env
API keys
Database credentials
Authentication secrets
Private tokens
```

Add sensitive files to `.gitignore` before pushing the project to GitHub.

## License

MIT License

## Author

**Mehedi Hasan Topu**
