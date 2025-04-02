# Password Strength Analyzer and Generator

This Python program analyzes the strength of passwords and suggests stronger alternatives. It uses various metrics including entropy calculation, pattern detection, and cross-referencing with known breached passwords.

## Features

- Password strength analysis using multiple metrics
- Entropy calculation
- Pattern detection
- Dictionary word checking
- Have I Been Pwned API integration
- Strong password generation
- Time-to-crack estimation
- Modern web interface with real-time analysis

## Requirements
- First [Download rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)
- Python 3.7+
- Required packages listed in `requirements.txt`

## Installation

1. Clone this repository or download the files
2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```
3. (Optional) Create a `.env` file with your Have I Been Pwned API key:
   ```
   HIBP_API_KEY=your_api_key_here
   ```

## Usage

### Command Line Interface
Run the program in command line mode:
```bash
python password_analyzer.py
```

### Web Interface
Run the Flask web application:
```bash
python app.py
```
Then open your web browser and navigate to `http://localhost:5000`

The web interface provides:
- Real-time password analysis
- Visual strength indicators
- One-click password copying
- Detailed breakdown of password characteristics
- Modern, responsive design

The program will prompt you to enter a password to analyze. It will then:
1. Analyze the password strength
2. Show various metrics including entropy and time-to-crack
3. Suggest a stronger password
4. Compare the security of both passwords

To quit the program, enter 'q' when prompted for a password.

## Security Note

This program is for educational purposes only. Never share your actual passwords with anyone or any program. The program does not store or transmit passwords in any way except for the Have I Been Pwned API check, which only sends the first 5 characters of the password's SHA-1 hash.

## License

MIT License 
