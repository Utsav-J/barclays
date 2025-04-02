import zxcvbn
import secrets
import string
import re
import nltk
from typing import Tuple, Dict, List
import requests
import os
from dotenv import load_dotenv
import math

# Download required NLTK data
try:
    nltk.data.find('corpora/words')
except LookupError:
    nltk.download('words')

class PasswordAnalyzer:
    def __init__(self):
        self.common_patterns = [
            r'[a-z]+',  # lowercase letters
            r'[A-Z]+',  # uppercase letters
            r'\d+',     # numbers
            r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?]'  # special characters
        ]
        self.character_sets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'special': '!@#$%^&*()_+-=[]{}|;:,.<>?'
        }
        self.substitutions = {
            'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 'b': '8'
        }
        self.words = set(nltk.corpus.words.words())
        load_dotenv()
        self.hibp_api_key = os.getenv('HIBP_API_KEY')
        
        # Initialize RockYou database
        self.rockyou_path = "rockyou.txt"
        self.rockyou_hashes = set()
        try:
            with open(self.rockyou_path, 'r', encoding='latin-1') as f:
                for line in f:
                    self.rockyou_hashes.add(line.strip())
        except FileNotFoundError:
            print("Warning: rockyou.txt not found. RockYou database check will be skipped.")

    def calculate_entropy(self, password: str) -> float:
        """Calculate Shannon entropy of the password."""
        if not password:
            return 0.0
        
        # Count frequency of each character
        char_freq = {}
        for char in password:
            char_freq[char] = char_freq.get(char, 0) + 1
        
        # Calculate entropy
        length = len(password)
        entropy = 0.0
        for freq in char_freq.values():
            prob = freq / length
            entropy -= prob * math.log2(prob)
        
        return entropy

    def analyze_patterns(self, password: str) -> List[str]:
        """Analyze password for common patterns."""
        patterns_found = []
        for pattern in self.common_patterns:
            if re.search(pattern, password):
                patterns_found.append(pattern)
        return patterns_found

    def check_dictionary_words(self, password: str) -> List[str]:
        """Check if password contains dictionary words."""
        words_found = []
        # Check for words of length 4 or more
        for i in range(len(password) - 3):
            for j in range(i + 4, len(password) + 1):
                word = password[i:j].lower()
                if word in self.words:
                    words_found.append(word)
        return words_found

    def check_haveibeenpwned(self, password: str) -> bool:
        """Check if password has been exposed in data breaches."""
        if not self.hibp_api_key:
            return False
        
        # Hash the password using SHA-1
        import hashlib
        sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1_password[:5], sha1_password[5:]
        
        # Check against Have I Been Pwned API
        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        headers = {'hibp-api-key': self.hibp_api_key}
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                hashes = response.text.split('\r\n')
                for hash_line in hashes:
                    if hash_line.split(':')[0] == suffix:
                        return True
        except:
            pass
        return False

    def check_rockyou(self, password: str) -> bool:
        """Check if password exists in RockYou database."""
        return password in self.rockyou_hashes

    def generate_strong_password(self, weak_password: str) -> str:
        """Generate a strong password based on the weak password."""
        # Start with the weak password
        new_password = weak_password
        
        # Apply random capitalization
        new_password = ''.join(
            c.upper() if secrets.randbelow(2) else c.lower()
            for c in new_password
        )
        
        # Apply character substitutions
        for old, new in self.substitutions.items():
            if secrets.randbelow(2):
                new_password = new_password.replace(old, new)
                new_password = new_password.replace(old.upper(), new)
        
        # Add random special characters
        special_chars = self.character_sets['special']
        new_password += secrets.choice(special_chars)
        
        # Ensure minimum length
        while len(new_password) < 12:
            new_password += secrets.choice(string.ascii_letters + string.digits + special_chars)
        
        return new_password

    def estimate_time_to_crack(self, password: str) -> str:
        """Estimate time to crack the password."""
        zxcvbn_result = zxcvbn.zxcvbn(password)
        crack_time = zxcvbn_result['crack_times_display']['offline_slow_hashing_1e4_per_second']
        return crack_time

    def analyze_password(self, password: str) -> Dict:
        """Perform comprehensive password analysis."""
        analysis = {
            'original_password': password,
            'entropy': self.calculate_entropy(password),
            'patterns_found': self.analyze_patterns(password),
            'dictionary_words': self.check_dictionary_words(password),
            'is_breached': self.check_haveibeenpwned(password),
            'in_rockyou': self.check_rockyou(password),
            'time_to_crack': self.estimate_time_to_crack(password),
            'zxcvbn_score': zxcvbn.zxcvbn(password)['score'],
            'suggested_password': self.generate_strong_password(password)
        }
        return analysis

def main():
    analyzer = PasswordAnalyzer()
    
    print("Welcome to the Password Strength Analyzer!")
    print("This tool will analyze your password and suggest a stronger version.")
    
    while True:
        password = input("\nEnter a password to analyze (or 'q' to quit): ")
        if password.lower() == 'q':
            break
            
        analysis = analyzer.analyze_password(password)
        
        print("\n=== Password Analysis Results ===")
        print(f"Original Password: {analysis['original_password']}")
        print(f"Entropy: {analysis['entropy']:.2f} bits")
        print(f"Time to Crack: {analysis['time_to_crack']}")
        print(f"zxcvbn Score: {analysis['zxcvbn_score']}/4")
        
        if analysis['patterns_found']:
            print("\nPatterns Found:")
            for pattern in analysis['patterns_found']:
                print(f"- {pattern}")
        
        if analysis['dictionary_words']:
            print("\nDictionary Words Found:")
            for word in analysis['dictionary_words']:
                print(f"- {word}")
        
        if analysis['is_breached']:
            print("\n⚠️ WARNING: This password has been exposed in data breaches!")
        
        if analysis['in_rockyou']:
            print("\n⚠️ WARNING: This password exists in the RockYou database!")
        
        print("\n=== Suggested Strong Password ===")
        print(f"New Password: {analysis['suggested_password']}")
        print(f"Time to Crack: {analyzer.estimate_time_to_crack(analysis['suggested_password'])}")
        print(f"zxcvbn Score: {zxcvbn.zxcvbn(analysis['suggested_password'])['score']}/4")

if __name__ == "__main__":
    main() 