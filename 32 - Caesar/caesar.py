import nltk
import logging
from nltk.corpus import words
from string import ascii_uppercase
from multiprocessing import Pool, cpu_count

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Download the word corpus if not already available
nltk.download('words')

class WordChecker:
    """Class to check if the decrypted text contains meaningful English words."""
    
    def __init__(self):
        # Convert the word list to lowercase for case-insensitive comparison
        self.word_list = set(word.lower() for word in words.words())
        # Add domain-specific or custom words like "CYBERSECURITY"
        self.custom_words = set(["cybersecurity", "encryption", "decryption", "security", "information"])

    def is_meaningful(self, text):
        """Check if the decrypted text contains meaningful words."""
        try:
            # Convert the text to lowercase for case-insensitive comparison
            text_lower = text.lower()
            
            # First, check if the entire text is a meaningful word (useful for long words like "cybersecurity")
            if text_lower in self.word_list or text_lower in self.custom_words:
                return True

            # Split the text and check individual words
            words_in_text = text_lower.split()  # Split based on spaces (if present)
            valid_words_count = sum(1 for word in words_in_text if word in self.word_list or word in self.custom_words)

            # If any of the words are valid, consider the text meaningful
            if valid_words_count > 0:
                return True

            return False
        except Exception as e:
            logging.error(f"Error in is_meaningful: {e}")
            return False


class DecryptionHelper:
    """Class to handle Caesar cipher encryption and decryption."""
    
    def __init__(self, checker):
        self.checker = checker

    def caesar_decrypt(self, ciphertext, key):
        """Decrypt a given ciphertext using the Caesar cipher with the specified key."""
        try:
            plaintext = str()
            for character in ciphertext:
                if character in ascii_uppercase:
                    # Decryption formula: (position - key) % 26
                    q = (ord(character) - ord('A') - key) % 26
                    plaintext += chr(q + ord('A'))
                else:
                    plaintext += character  # Non-alphabetic characters stay the same
            return plaintext
        except Exception as e:
            logging.error(f"Error in caesar_decrypt for key {key}: {e}")
            return None

    def caesar_encrypt(self, plaintext, key):
        """Encrypt a given plaintext using the Caesar cipher with the specified key."""
        try:
            ciphertext = str()
            for character in plaintext:
                if character in ascii_uppercase:
                    # Encryption formula: (position + key) % 26
                    q = (ord(character) - ord('A') + key) % 26
                    ciphertext += chr(q + ord('A'))
                else:
                    ciphertext += character  # Non-alphabetic characters stay the same
            logging.info(f"Encrypted plaintext: {plaintext} -> Ciphertext: {ciphertext} with key {key}")
            return ciphertext
        except Exception as e:
            logging.error(f"Error in caesar_encrypt for key {key}: {e}")
            return None

    def try_decrypt(self, ciphertext, key):
        """Try to decrypt the ciphertext with a specific key and check if it's meaningful."""
        try:
            decrypted_text = self.caesar_decrypt(ciphertext, key)
            if decrypted_text and self.checker.is_meaningful(decrypted_text):
                logging.info(f"Found potential solution with key {key}: {decrypted_text}")
                return key, decrypted_text
            return None
        except Exception as e:
            logging.error(f"Error in try_decrypt for key {key}: {e}")
            return None


class CaesarCipherCracker:
    """Main class to orchestrate the decryption process."""
    
    def __init__(self, ciphertext):
        self.ciphertext = ciphertext
        self.word_checker = WordChecker()
        self.decryption_helper = DecryptionHelper(self.word_checker)

    def auto_crack_caesar_multiprocessing(self):
        """Attempt to crack the Caesar cipher using multiprocessing."""
        logging.info("Starting multiprocessing brute-force Caesar cipher decryption")

        try:
            with Pool(cpu_count()) as pool:
                # Generate the inputs for each process (ciphertext and each key from 0 to 25)
                results = pool.starmap(self.decryption_helper.try_decrypt, [(self.ciphertext, key) for key in range(26)])

            # Filter out None results and return the first meaningful decryption found
            results = [result for result in results if result is not None]

            if results:
                logging.info(f"Decryption successful. Found result: {results[0]}")
                return results[0]  # Return the first valid key and decrypted message
            else:
                logging.warning("Failed to crack the cipher.")
                return None, None
        except Exception as e:
            logging.error(f"Error in auto_crack_caesar_multiprocessing: {e}")
            return None, None


if __name__ == '__main__':
    try:
        # Define the plaintext and key
        plaintext = "CYBERSECURITY"
        key = 23

        # Create the main CaesarCipherCracker instance
        cracker = CaesarCipherCracker(None)

        # Encrypt the plaintext
        encrypted_message = cracker.decryption_helper.caesar_encrypt(plaintext, key)

        # Use the encrypted message for cracking
        cracker.ciphertext = encrypted_message

        # Attempt to automatically crack the cipher via brute force using multiprocessing
        cracked_key, cracked_message = cracker.auto_crack_caesar_multiprocessing()

        if cracked_key is not None:
            logging.info(f"\nThe cracked key is: {cracked_key}")
            logging.info(f"The cracked message is: {cracked_message}")
        else:
            logging.warning("Failed to crack the cipher.")
    except Exception as e:
        logging.error(f"An error occurred in the main execution: {e}")
