# Assignment (Optional)

## Brief

Implement JWT authentication in a Spring Boot application with token generation, validation, and protected endpoints.

1. **JWT Token Generation and Login Endpoint**
   - Use your existing project (e.g., simple-crm or any REST API project)
   - Add JWT dependencies to `pom.xml`:
     - `io.jsonwebtoken:jjwt-api:0.11.5`
     - `io.jsonwebtoken:jjwt-impl:0.11.5` (runtime scope)
     - `io.jsonwebtoken:jjwt-jackson:0.11.5` (runtime scope)
   - Add JWT configuration to `application.properties`:
     - `jwt.secret` (use a long random string)
     - `jwt.expiration-ms` (set to 3600000 for 1 hour)
   - Create DTOs:
     - `LoginRequest` class with username and password fields
     - `TokenResponse` class with token field
   - Create a `JwtService` class with methods:
     - `generateToken(String username)` - generates JWT token with username and expiry
     - `extractUsername(String token)` - extracts username from token
     - `isTokenValid(String token)` - validates token signature and expiry
   - Create an `AuthController` with POST `/auth/login` endpoint:
     - Accept LoginRequest in request body
     - Validate credentials (use simple check: username="user", password="password")
     - Return TokenResponse with generated JWT token if valid
     - Return 401 Unauthorized if invalid
   - Test with Postman:
     - Send POST to `/auth/login` with valid credentials
     - Verify you receive a JWT token in response
     - Copy the token for next part

2. **JWT Authentication Filter and Protected Endpoints**
   - Create a `JwtAuthFilter` class extending `OncePerRequestFilter`:
     - Extract token from `Authorization: Bearer <token>` header
     - Validate token using JwtService
     - If valid, set authentication in SecurityContext
     - If invalid or missing, continue filter chain
   - Update `SecurityConfig`:
     - Disable CSRF
     - Set session policy to STATELESS
     - Configure authorization rules:
       - Allow `/auth/login` without authentication
       - Require authentication for `/api/**` endpoints
     - Add JWT filter before UsernamePasswordAuthenticationFilter
   - Create a simple protected endpoint:
     - `GET /api/hello` that returns "Hello! JWT authentication successful."
   - Test the complete flow with Postman:
     - Try accessing `/api/hello` without token (should get 401 Unauthorized)
     - Login at `/auth/login` to get token
     - Access `/api/hello` with header `Authorization: Bearer <your-token>` (should get 200 OK)
     - Document your testing results with descriptions or screenshots

## Submission (Optional)

- Submit the URL of the GitHub Repository that contains your work to NTU black board.
- Should you reference the work of your classmate(s) or online resources, give them credit by adding either the name of your classmate or URL.

## References
- Java: https://docs.oracle.com/javase/
- Spring Boot: https://docs.spring.io/spring-boot/docs/current/reference/html/
- PostgreSQL: https://www.postgresql.org/docs/
- OWASP: https://cheatsheetseries.owasp.org/