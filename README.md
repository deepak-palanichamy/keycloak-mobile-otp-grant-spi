# Keycloak Mobile Number OTP Grant SPI

A custom OAuth2 Grant Type SPI (Service Provider Interface) for Keycloak that enables mobile number-based One-Time Password (OTP) authentication. This grant type allows applications to authenticate users using their mobile number and a one-time password, implementing a streamlined authentication flow for mobile-first applications.

## Features

- **Custom OAuth2 Grant Type**: Implements `urn:custom:mobilenumber_otp` grant for Keycloak
- **Mobile-First Authentication**: Authenticate users via mobile number and OTP
- **Automatic User Provisioning**: Automatically creates users if they don't exist (based on mobile number)
- **External OTP Verification**: Integrates with external OTP verification services via HTTPS
- **Mobile Number Validation**: Validates national numbers against the supplied ISO 3166-1 alpha-2 region
- **E.164 Canonicalization**: Converts validated numbers to E.164 before OTP verification and user lookup
- **Secure Communication**: Uses HTTPS with shared secret for external service communication
- **Configurable Timeout**: Customizable request timeout for external service calls
- **Event Tracking**: Full Keycloak event logging for authentication attempts and errors

## Requirements

- **Keycloak**: Version 26.6.4 (tested with this version)
- **Java**: JDK 21+
- **Maven**: 3.6.0 or later
- **External OTP Service**: A secure HTTPS endpoint that verifies OTP for a given mobile number

## Installation

### Building the Project

```bash
mvn clean package
```

This will generate `keycloak-mobile-otp-grant-spi-1.0.0-SNAPSHOT.jar` in the `target/` directory.

### Deploying to Keycloak

1. Copy the JAR file to your Keycloak providers directory:
   ```bash
   cp target/keycloak-mobile-otp-grant-spi-1.0.0-SNAPSHOT.jar $KEYCLOAK_HOME/providers/
   ```

2. If using Docker:
   ```dockerfile
   FROM keycloak:26.6.4
   COPY keycloak-mobile-otp-grant-spi-1.0.0-SNAPSHOT.jar /opt/keycloak/providers/
   RUN /opt/keycloak/bin/kc.sh build
   ```

3. Restart Keycloak to load the new grant type

## Configuration

Configure the grant type via Keycloak configuration file (`keycloak.conf`) or environment variables:

### Configuration Options

| Option | Environment Variable | Required | Description |
|--------|---------------------|----------|-------------|
| `verify-url` | `KC_OTP_VERIFY_URL` | Yes | HTTPS endpoint for OTP verification |
| `shared-secret` | `KC_OTP_SHARED_SECRET` | Yes | Shared secret sent as a Bearer token in the Authorization header |
| `timeout-seconds` | `KC_OTP_TIMEOUT_SECONDS` | No | Request timeout in seconds (default: 5) |

### Configuration Example

**Via keycloak.conf:**
```properties
spi-oauth2-grant-type-urn-custom-mobilenumber-otp-verify-url=https://otp-service.example.com/verify
spi-oauth2-grant-type-urn-custom-mobilenumber-otp-shared-secret=your-shared-secret-here
spi-oauth2-grant-type-urn-custom-mobilenumber-otp-timeout-seconds=10
```

**Via Environment Variables:**
```bash
export KC_OTP_VERIFY_URL=https://otp-service.example.com/verify
export KC_OTP_SHARED_SECRET=your-shared-secret-here
export KC_OTP_TIMEOUT_SECONDS=10
```

## Usage

### Token Request

Send a POST request to Keycloak's token endpoint with the custom grant type:

```bash
curl -X POST \
  https://keycloak.example.com/realms/your-realm/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:custom:mobilenumber_otp&client_id=your-client-id&country_iso=IN&mobile_number=9876543210&otp=123456&scope=openid+profile"
```

### Parameters

- `grant_type`: Must be `urn:custom:mobilenumber_otp`
- `client_id`: Your OAuth2 client ID
- `country_iso`: Required ISO 3166-1 alpha-2 country code, such as `IN` or `US`
- `mobile_number`: National mobile number for the supplied country, such as `9876543210`
- `otp`: One-time password sent to the mobile number
- `scope`: Optional. OpenID Connect scopes (default: `openid`)

The grant validates the number for `country_iso`, accepts it only when
`libphonenumber` identifies it as a mobile number, and converts it to E.164
for OTP verification and user lookup. For example, `country_iso=IN` and
`mobile_number=9876543210` become `+919876543210`.

### Response

On successful authentication:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cC...",
  "token_type": "Bearer",
  "expires_in": 300,
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cC...",
  "scope": "openid profile"
}
```

### Error Responses

| Error | Status | Description |
|-------|--------|-------------|
| `invalid_request` | 400 | Missing or invalid country_iso/mobile_number/otp parameters |
| `invalid_grant` | 401 | Invalid or expired OTP |
| `invalid_client` | 401 | Invalid client credentials |
| `server_error` | 500 | External OTP service error or interrupted request |
| `server_error` | 502 | OTP service could not be reached |
| `server_error` | 504 | OTP service request timed out |

## Architecture

### Components

- **MobileNumberOTPGrantType**: Main grant type implementation extending `OAuth2GrantTypeBase`
  - Validates the country ISO and mobile number, then canonicalizes the number to E.164
  - Verifies OTP with external service
  - Creates or retrieves user based on mobile number
  - Issues access tokens via Keycloak's TokenManager

- **MobileNumberOTPGrantTypeFactory**: Factory implementation for grant type instantiation
  - Reads configuration from `keycloak.conf` or environment variables
  - Validates configuration on initialization
  - Creates `MobileNumberOTPGrantType` instances for each session

### Validation

- **Country**: Must be a supported ISO 3166-1 alpha-2 region code. Input is trimmed and normalized to uppercase.
- **Phone Number**: Parsed with `libphonenumber`, validated for the supplied region with `isValidNumberForRegion`, and required to have type `MOBILE`.
- **Canonical Format**: Valid numbers are converted to E.164, such as `+919876543210`.
- **OTP**: Passed to the external OTP service for verification.
- **HTTPS**: Requires HTTPS for external OTP service communication

### User Provisioning

- Users are automatically created if not found by mobile number
- The mobile number is stored as the user's `mobileNumber` attribute in E.164 format
- Existing users are looked up by their `mobileNumber` attribute

## Building

```bash
# Clean build
mvn clean package

# Skip tests (if any)
mvn clean package -DskipTests

# With specific Java version
mvn clean package -Djava.version=21
```

Output: `target/keycloak-mobile-otp-grant-spi-1.0.0-SNAPSHOT.jar`

## Project Structure

```text
keycloak-mobile-otp-grant-spi/
├── src/
│   └── main/
│       ├── java/com/residentnext/keycloak/grant/
│       │   ├── MobileNumberOTPGrantType.java          # Main grant implementation
│       │   └── MobileNumberOTPGrantTypeFactory.java   # Factory implementation
│       └── resources/
│           └── META-INF/services/
│               └── org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory
├── pom.xml                                             # Maven configuration
└── README.md                                           # This file
```

## External OTP Service Integration

Your external OTP verification service should:

1. **Accept HTTPS POST requests** with an `Authorization` header containing the configured shared secret as a Bearer token:
  
  ```http
  Authorization: Bearer your-shared-secret
  Content-Type: application/json
  ```

  The request body contains:

   ```json
   {
     "mobile_number": "+1234567890",
     "otp": "123456"
   }
   ```

2. **Return HTTP 200** with one of these plain-text response bodies for successful verification:

  ```text
   VERIFIED
   ```

   or:

  ```text
   ALREADY_VERIFIED
   ```

1. **Return any non-200 status** for an invalid or rejected OTP. The grant treats it as `invalid_grant` with HTTP 401.

## Troubleshooting

### Grant Type Not Available

- Ensure JAR is in `$KEYCLOAK_HOME/providers/`
- Verify Keycloak was restarted after deployment
- Check Keycloak logs for deployment errors

### Configuration Errors

- Verify both `verify-url` and `shared-secret` are configured
- Ensure `verify-url` uses HTTPS protocol
- Check that environment variables are correctly set

### OTP Verification Failures

- Verify external OTP service is reachable and returning valid responses
- Check network connectivity and firewall rules
- Verify `shared-secret` matches between Keycloak and OTP service
- Increase `timeout-seconds` if service is slow

### User Provisioning Issues

- Check user creation permissions in Keycloak realm
- Verify `country_iso` is a supported ISO 3166-1 alpha-2 code
- Verify `mobile_number` is a valid mobile number for that region
- Check Keycloak logs for detailed error messages

## Security Considerations

- **HTTPS Only**: External OTP service communication is enforced to use HTTPS
- **Shared Secret**: Use a strong, randomly generated shared secret
- **Timeout Configuration**: Set appropriate timeout values to prevent hanging requests
- **User Validation**: All input is validated before processing
- **Event Logging**: All authentication attempts are logged in Keycloak events

## License

This project is provided as-is. Please add appropriate license information here.

## Contributing

Contributions are welcome! Please ensure:

- Code follows Java conventions
- All validations are maintained
- Security best practices are followed
- Changes are tested with Keycloak 26.6.4+

## Support

For issues or questions, please refer to Keycloak documentation:

- [Keycloak OAuth2 Grant Types](https://www.keycloak.org/docs/latest/server_development/)
- [Keycloak SPI Development](https://www.keycloak.org/docs/latest/server_development/index.html#_providers)
