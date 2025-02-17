# **BYPASS-4XX** - Advanced 4XX HTTP Status Code Bypass Tool

![BYPASS-4XX Banner](https://img.shields.io/badge/Tool-BYPASS--4XX-blue.svg)

## Overview
**BYPASS-4XX** is an advanced Python tool designed to bypass common 4XX HTTP status codes (e.g., 403, 404) in web applications. This tool uses various techniques such as encoding, header manipulation, HTTP method tampering, and directory traversal to evade restrictions. It is optimized for penetration testers, security researchers, and ethical hackers.

## Features

### Core Features:
- **Multiple Bypass Techniques**: Leverages encoding, headers, HTTP method tampering, and directory traversal to bypass restrictions.
- **Concurrency**: Uses multithreading to test multiple payloads quickly.
- **Customizable Output**: Allows users to define output file names using `-of <filename.txt>`.
- **Stealth Mode**: Randomizes headers, user-agent, and supports IP spoofing to avoid detection.
- **Real-time Results**: Logs successful bypasses in an output file while showing failures on-screen.

### Advanced Features:
- **Header Manipulation**: Modifies headers such as `X-Forwarded-For`, `Referer`, and `User-Agent`.
- **Encoding Techniques**: Supports Hex, URL encoding, Base64, and null byte injection.
- **Path Obfuscation**: Uses double slashes (`//`), dots (`../`), and Unicode encoding.
- **Custom Method Testing**: Attempts alternative HTTP methods like `POST`, `PUT`, `TRACE`, `OPTIONS`.
- **Case Sensitivity**: Tests different case variations like `ADMIN`, `Admin`, `aDmIn`.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ram-prasad-sahoo/BYPASS-4XX.git
2. Navigate to the project directory:
   ```bash
   cd BYPASS-4XX
3. Install required dependencies:
   ```bash
   pip install -r requirements.txt

## Usage
   To run the tool, use the following command:
   ```bash
   python 4xxbypass.py -of outputfilename.txt
   ```
![BYPASS-4XX Banner](https://github.com/ram-prasad-sahoo/BYPASS-4XX/raw/main/tool.png)
