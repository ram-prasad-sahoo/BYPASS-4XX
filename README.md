# **BYPASS-4XX** - Advanced 4XX HTTP Status Code Bypass Tool

![BYPASS-4XX Banner](https://img.shields.io/badge/Tool-BYPASS--4XX-blue.svg)

## 📢Overview
**BYPASS-4XX** is an advanced Python tool designed to bypass common 4XX HTTP status codes (e.g., 403, 404) in web applications. This tool uses various techniques such as encoding, header manipulation, HTTP method tampering, and directory traversal to evade restrictions. It is optimized for penetration testers, security researchers, and ethical hackers.

## 🚀Features

### 🔑Core Features:
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

## 🛠️Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ram-prasad-sahoo/BYPASS-4XX.git
2. Navigate to the project directory:
   ```bash
   cd BYPASS-4XX
3. Install required dependencies:
   ```bash
   pip install -r requirements.txt

## ⚡Usage
   To run the tool, use the following command:
   ```bash
   usage: 4xxbypass.py [-h] -u URL -p PATH [-o OUTPUT] [-t THREADS] [--timeout TIMEOUT] [--proxy PROXY] [-ua USER_AGENT] [-v]

Advanced 4xx/3xx Bypass Tool with integrated techniques from multiple sources.

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL (e.g., https://example.com)
  -p PATH, --path PATH  Target path to test (e.g., /admin, /api/v1/users)
  -o OUTPUT, --output OUTPUT
                        Specify output file name to save results (e.g.,
                        results.txt)
  -t THREADS, --threads THREADS
                        Number of concurrent threads (default: 30)
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
  --proxy PROXY         Proxy server to use (e.g., http://127.0.0.1:8080)
  -ua USER_AGENT, --user-agent USER_AGENT
                        Custom User-Agent string
  -v, --verbose         Show failed attempts in output
   ```
![BYPASS-4XX Banner](https://github.com/ram-prasad-sahoo/BYPASS-4XX/raw/main/tool.png)
## 📄License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
## 👨‍💻Author

This tool was created by **Ram Prasad Sahoo**.

## 💬 **Support**

If you need help or have any questions, feel free to reach out to me:

- **GitHub Issues**: You can open an issue on the [GitHub Issues page](https://github.com/ram-prasad-sahoo/BYPASS-4XX/issues) for technical support or reporting bugs.
  
- **Email**: You can contact me directly by clicking the button below:

[![Contact via Gmail](https://img.shields.io/badge/Contact%20via-Gmail-c14438?style=flat&logo=gmail&logoColor=white)](mailto:ramprasadsahoo42@gmail.com)

- **LinkedIn**: Connect with me on LinkedIn by clicking the button below:

[![Connect via LinkedIn](https://img.shields.io/badge/Connect%20via-LinkedIn-0077b5?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/ramprasadsahoo/)

---

I aim to respond as quickly as possible, and your feedback is highly appreciated. Thank you for using **BYPASS-4XX**!



## Disclaimer

**BYPASS-4XX** is a security testing tool intended for ethical hacking and penetration testing in environments where you have explicit permission to do so. 

The author is not responsible for any misuse of this tool. Unauthorized use of this tool for malicious purposes is illegal and against ethical guidelines. Please ensure that you have proper authorization before using this tool on any website or network.

Use at your own risk.
## ⭐Contributions
Contributions are welcome! If you want to improve or add new features to the tool, feel free to fork the repository, make changes, and submit a pull request.
