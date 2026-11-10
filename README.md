# vuln-JWT-Analyzer
Analyzes JSON Web Tokens (JWTs) for vulnerabilities, including weak algorithms, missing signature verification, and exposed secrets. Decodes the JWT and highlights potential issues. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowGuard-AI/vuln-jwt-analyzer`
`pip install -r requirements.txt`

## Usage
`python main.py <jwt_token> [params]`

Example: `python main.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature --secret your-256-bit-secret`

The header and payload must each decode to a JSON object; a token whose header or payload decodes to any other JSON value is reported as an invalid JWT format and exits 1. With `--target_url`, the tool sends one GET request carrying the token as a Bearer token and reports only the response status.

## Parameters
- `jwt_token` (positional, required): The JWT token to analyze.
- `-h`: Show help message and exit
- `--secret`: The secret key used to sign the JWT (optional). HMAC verification is supported for HS256, HS384, and HS512 only.
- `--target_url`: The target URL to perform a vulnerability scan (optional).
- `--verbose`: Enable verbose output (debug logging).

## License
MIT License (see LICENSE).
