import argparse
import base64
import hashlib
import hmac
import json
import logging
import sys

try:
    import requests
except ImportError:
    print("Error: The 'requests' library is required.")
    print("Please install it using: pip install requests")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class JWTAnalyzer:
    """
    Analyzes JSON Web Tokens (JWTs) for vulnerabilities.
    """

    def __init__(self, jwt_token):
        """
        Initializes the JWTAnalyzer with the JWT token.

        Args:
            jwt_token (str): The JWT token to analyze.
        """
        self.jwt_token = jwt_token
        self.header = None
        self.payload = None
        self.signature = None
        self.raw_signing_input = None
        self.malformed_claim = False

    def decode_jwt(self):
        """
        Decodes the JWT token into its header, payload, and signature components.
        Handles errors gracefully if the JWT format is invalid.
        """
        try:
            parts = self.jwt_token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format: JWT must have three parts separated by dots.")

            self.header = self.decode_part(parts[0])
            self.payload = self.decode_part(parts[1])
            self.signature = parts[2]
            self.raw_signing_input = parts[0] + '.' + parts[1]

        except ValueError as e:
            logging.error(f"Error decoding JWT: {e}")
            return False
        except Exception as e:
            logging.exception(f"Unexpected error decoding JWT: {e}")  # More detailed logging
            return False
        return True

    def decode_part(self, encoded_part):
        """
        Decodes a base64url encoded part of the JWT.

        Args:
            encoded_part (str): The base64url encoded string.

        Returns:
            dict: The decoded JSON object.

        Raises:
            ValueError: If the input is not a valid base64url string.
            json.JSONDecodeError: If the decoded string is not valid JSON.
        """
        try:
            # Add padding if necessary to ensure correct base64 decoding
            padding_needed = len(encoded_part) % 4
            if padding_needed:
                encoded_part += '=' * (4 - padding_needed)
            
            decoded_bytes = base64.urlsafe_b64decode(encoded_part)
            decoded_string = decoded_bytes.decode('utf-8')
            # Nothing here forces the JSON to be an object. A token whose
            # header decodes to a list or a number passes this function and
            # then fails later when analyze_algorithm calls .get on it.
            return json.loads(decoded_string)

        except base64.binascii.Error:
            raise ValueError("Invalid base64url encoding")
        except json.JSONDecodeError:
            raise json.JSONDecodeError("Invalid JSON format", doc=decoded_string, pos=0)

    def analyze_algorithm(self):
        """
        Analyzes the 'alg' (algorithm) field in the JWT header for potential weaknesses.
        """
        if not self.header:
            logging.warning("Header is not decoded. Decode JWT first.")
            return

        alg = self.header.get('alg')
        if not alg:
            logging.warning("JWT header missing 'alg' field.")
            return

        logging.info(f"Algorithm used: {alg}")

        # Algorithm names are matched exactly, case included. A header
        # that says None or hs256 lands in the unknown branch below, even
        # though a lenient verifier might treat them as the real thing.
        if alg == 'none':
            logging.warning("Vulnerability: 'alg' is set to 'none', indicating no signature verification is performed.")
        elif alg in ['HS256', 'HS384', 'HS512']:
            logging.info("Algorithm uses HMAC. Check for key strength and proper key management practices.")
        elif alg in ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']:
            logging.info("Algorithm uses asymmetric cryptography. Check for valid and trusted certificates.")
        else:
            logging.warning(f"Unknown algorithm: {alg}. Investigate further.")

    def check_signature_verification(self, secret=None):
        """
        Attempts to verify the JWT signature using a provided secret.
        This is a basic check and might not cover all possible scenarios.
        """
        if not self.header or not self.payload or not self.signature:
            logging.warning("JWT components are not decoded. Decode JWT first.")
            return False

        if not secret:
            logging.warning("No secret provided for signature verification. Provide a secret to check.")
            return False

        alg = self.header.get('alg')
        hash_for_alg = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}
        if alg not in hash_for_alg:
            logging.warning(f"Signature verification not supported for algorithm '{alg}' with an HMAC secret. Asymmetric algorithms (RS and ES families) need a public key, not a shared secret, so no HMAC check was run.")
            return False

        try:
            # Verify over the token's original encoded segments exactly as
            # received. Re-serializing the decoded JSON would change the
            # signed bytes whenever the issuer's key order differs.
            message = self.raw_signing_input

            expected_signature = hmac.new(secret.encode('utf-8'), message.encode('utf-8'), hash_for_alg[alg]).digest()
            expected_signature_b64 = base64.urlsafe_b64encode(expected_signature).rstrip(b'=').decode('utf-8')
            
            if expected_signature_b64 == self.signature:
                logging.info("Signature verification successful.")
                return True
            else:
                logging.warning("Signature verification failed.")
                return False

        except Exception as e:
            logging.exception(f"Error during signature verification: {e}")
            return False

    def analyze_payload(self):
        """
        Analyzes the JWT payload for sensitive information and potential vulnerabilities.
        """
        if not self.payload:
            logging.warning("Payload is not decoded. Decode JWT first.")
            return

        logging.info("Analyzing JWT payload...")

        # Check for common claims like 'exp' (expiration time)
        if 'exp' in self.payload:
            expiration_time = self.payload['exp']
            # bool is named first because Python booleans are integers. A
            # token with exp set to true would pass a plain int check and
            # then compare as 1 against the current time.
            if isinstance(expiration_time, bool) or not isinstance(expiration_time, (int, float)):
                logging.error("Malformed token: the 'exp' claim is not a number, so the expiration cannot be checked.")
                self.malformed_claim = True
            else:
                logging.info(f"Expiration Time (exp): {expiration_time}")

                # Basic check if the token is expired
                import time
                if expiration_time < time.time():
                    logging.warning("Token is expired.")
                else:
                    logging.info("Token is not expired.")

        # Check for other potentially sensitive claims. Claim values are
        # never printed: the finding is the claim name and its presence.
        sensitive_claims = ['sub', 'user_id', 'email', 'username']  # Add more as needed
        for claim in sensitive_claims:
            if claim in self.payload:
                logging.info(f"Found sensitive claim: {claim} (value present, not shown)")

        # Implement more sophisticated checks based on your application's context

    def run_vulnerability_scan(self, target_url):
        """
        Simulates running a vulnerability scan against a target URL using the JWT.
        (This is a placeholder and needs to be implemented with actual vulnerability scanning logic.)

        Args:
            target_url (str): The URL to scan.
        """
        try:
            headers = {'Authorization': f'Bearer {self.jwt_token}'}
            response = requests.get(target_url, headers=headers, timeout=10)

            # Only the status is reported. Response bodies are never
            # logged, and a status code alone is not a scan outcome.
            if response.status_code == 200:
                logging.info(f"Target {target_url} responded with status 200 to the scan request carrying the token.")
            else:
                logging.warning(f"Target {target_url} responded with status {response.status_code} to the scan request carrying the token.")

        except requests.exceptions.RequestException as e:
            logging.error(f"Error during vulnerability scan: {e}")

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Analyze JSON Web Tokens (JWTs) for vulnerabilities.')
    parser.add_argument('jwt_token', help='The JWT token to analyze.')
    parser.add_argument('--secret', help='The secret key used to sign the JWT (optional).', required=False)
    parser.add_argument('--target_url', help='The target URL to perform a vulnerability scan (optional).', required=False)
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output (debug logging).')
    return parser

def main():
    """
    Main function to execute the JWT analyzer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    jwt_token = args.jwt_token
    secret = args.secret
    target_url = args.target_url

    analyzer = JWTAnalyzer(jwt_token)

    if not analyzer.decode_jwt():
        logging.error("Failed to decode the JWT. Exiting.")
        sys.exit(1)

    analyzer.analyze_algorithm()
    analyzer.analyze_payload()

    if secret:
        analyzer.check_signature_verification(secret)
    else:
        logging.warning("No secret provided. Signature verification cannot be performed.")

    if target_url:
        analyzer.run_vulnerability_scan(target_url)

    # The malformed claim exit comes after the optional target request on
    # purpose: the scan still runs, and the exit code is what carries the
    # malformed verdict back to whoever called this.
    if analyzer.malformed_claim:
        logging.error("JWT analysis finished with a malformed claim. See the malformed token report above.")
        sys.exit(1)

    logging.info("JWT analysis completed.")


if __name__ == "__main__":
    # Example usage (you'd run this from the command line)
    # python main.py <jwt_token> --secret <secret_key> --target_url <url>
    # Example JWT:
    # eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

    # Example usage with verbose logging:
    # python main.py <jwt_token> --secret <secret_key> --target_url <url> --verbose
    main()