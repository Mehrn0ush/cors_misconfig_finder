# CORS Misconfig Finder

**Version**: 1.0.0  
**Author**: Mehrnoush ([Mehrnoush.vaseghi@gmail.com](mailto:Mehrnoush.vaseghi@gmail.com) | [Medium](https://medium.com/@Mehrnoush) | [GitHub](https://github.com/Mehrn0ush))

## Description
CORS Misconfig Finder is a tool designed to detect various CORS (Cross-Origin Resource Sharing) misconfigurations that can potentially expose your application to security risks.

## Misconfigurations Identified
1. **Reflected Origin**: Checks if the server reflects the `Origin` header value in `Access-Control-Allow-Origin`.
2. **Trusted Subdomains**: Checks if subdomains are allowed as origins, which might be an indicator of overly permissive configurations.
3. **Regexp Bypass**: Tests for regular expression bypasses where the origin matches a regex pattern used by the server.
4. **Null Origin**: Checks if the server allows `null` as a valid origin.
5. **Breaking TLS**: Checks if the server allows non-HTTPS origins even if the site itself uses HTTPS.
6. **Advanced Regexp Bypass**: Tests more sophisticated regex bypass attempts.
7. **Pre-domain Bypass**: Checks if the server incorrectly parses origins that prepend attacker domains.
8. **Post-domain Bypass**: Similar to pre-domain bypass but appends attacker domains.
9. **Backtick Bypass**: Tests if backticks in the origin can bypass CORS checks.
10. **Unescaped Dot Bypass**: Checks if unescaped dots in the origin can bypass CORS checks.
11. **Underscore Bypass**: Checks if underscores in the origin can bypass CORS checks.
12. **Invalid Value**: Uses an invalid origin provided by the user to test server response.
13. **Wildcard Value**: Checks if the server uses `*` as `Access-Control-Allow-Origin`.
14. **Third-party Allowance Test**: Tests if third-party domains (provided by the user) are allowed as origins.
15. **HTTP Allowance Test**: Checks if the server allows HTTP origins when it should only allow HTTPS.

## Usage

### Arguments
- `url` (required): The target URL to probe.
- `--custom-headers, -c`: Custom headers to include in the requests, provided in a format where headers are separated by `\n`.
- `--cookie, -k`: Cookie to include in the requests.
- `--rate-limit, -r`: Rate limit between requests in milliseconds.
- `--method, -m`: HTTP method to use (default is GET).
- `--proxy, -p`: Proxy URL to use for the requests.
- `--silent, -s`: Silent mode, suppresses the banner.
- `--no-color, -n`: Disable color in output.
- `--output, -o`: Output file to save the results.
- `--thirdparty`: Third-party domain to test.
- `--invalid-origin`: Invalid origin to test.

### Example Command
To run the program with custom headers such as Cookie and Authorization, use the following command:

```sh
cargo run -- https://www.targetURL.com \
    --thirdparty http://example-thirdparty.com \
    --invalid-origin http://example-invalid-origin.com \
    --custom-headers "Authorization: Bearer token123\nAnother-Header: value" \
    --cookie "sessionId=abc123"
```

You can also run the program with or without the --thirdparty and --invalid-origin arguments. The default values will be used if these arguments are not provided:

```sh
cargo run -- https://target.com

```


cargo run --: Runs the Rust program using Cargo.
https://www.targetURL.com: The target URL to probe.
--thirdparty http://example-thirdparty.com: Sets the third-party domain to test.
--invalid-origin http://example-invalid-origin.com: Sets the invalid origin to test.
--custom-headers "Authorization: Bearer token123\nAnother-Header: value": Adds custom headers to the request. Note the \n is used to separate multiple headers.
--cookie "sessionId=abc123": Sets the Cookie header for the request.

or 

```sh
./cors_misconf_finder https://target.com \
    --thirdparty http://example-thirdparty.com \
    --invalid-origin http://example-invalid-origin.com \
    --custom-headers "Authorization: Bearer token123\nAnother-Header: value" \
    --cookie "sessionId=abc123" \
    --rate-limit 1000 \
    --method GET \
    --proxy http://127.0.0.1:8080 \
    --output results.txt

```

Additional Notes
Headers: Ensure to format the custom headers correctly, separating multiple headers with \n.
Quotes: Use double quotes around the headers and cookie values to ensure they are interpreted correctly by the command line.
Escape Characters: The \n escape sequence is necessary to denote a new line within a command-line argument, allowing you to specify multiple headers.
License
This project is licensed under the MIT License.

Contributing
Contributions are welcome! Please submit a pull request or open an issue to discuss any changes.

Contact
For any queries or issues, please reach out to Mehrnoush at Mehrnoush.vaseghi@gmail.com.

Thank you for using CORS Misconfig Finder! Your feedback and contributions are highly appreciated.