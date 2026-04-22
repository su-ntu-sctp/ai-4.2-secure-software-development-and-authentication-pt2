# Module 4 – Lesson 4.2
# Spring Security Part 2: JWT Authentication & Authorization

---

## Lesson Overview

In this lesson, you will implement **JWT (JSON Web Token)** authentication in a Spring Boot application so that users can log in once, receive a token, and then use that token to access protected REST endpoints without using server-side sessions. We will begin with a small, standalone example to learn the complete JWT flow (generate token → send token → validate token → access protected endpoint), and then we will apply the same approach to **one or two simple endpoints** in our existing `simple-crm` project so you can see how JWT fits into a real application.

---

## Lesson Objectives

By the end of this lesson, learners will be able to:

1. **Explain** how JWT supports stateless authentication in REST APIs
2. **Implement** JWT token generation and validation in Spring Security
3. **Secure** one or two REST endpoints using JWT and call them from Postman
4. **Apply** the same JWT flow to simple endpoints in the Simple CRM project

---

## Prerequisites

You should already be comfortable with Spring Boot REST controllers, Spring Security fundamentals (basic auth and route protection), and the overall structure of the `simple-crm` project (controller → service → repository).

---

## Part 1: Why JWT Instead of Basic Authentication?

Basic authentication is useful for learning because it is simple, but it is not a great fit for modern REST APIs. In basic auth, the client sends the username and password on every request, which is not ideal. JWT is a common alternative because the client sends credentials once (during login), receives a signed token from the server, and then uses that token on subsequent requests. This keeps the server **stateless** (no session stored on the server) and makes the API easier to scale.

---

## Part 2: Stateless Authentication Mental Model (Session vs JWT)

In session-based authentication, the server "remembers" the user by storing session state after login. The client only needs to send a session identifier, and the server uses it to retrieve the session from memory or a session store. In JWT-based authentication, the server does not store a session. Instead, the server issues a token that contains user identity information (claims) and a signature. On every request, the server validates the token signature and expiry; if valid, the server treats the user as authenticated.

---

## Part 3: What a JWT Looks Like (Header, Payload, Signature)

A JWT is a string made of three Base64URL-encoded parts separated by dots:

```
header.payload.signature
```

The **header** usually contains metadata such as the signing algorithm. The **payload** contains claims such as the username and expiry time. The **signature** is generated using a secret key so that the token cannot be tampered with. You do not need to manually craft these parts in our lesson; the JWT library will generate and validate them for us, but you must understand what the token represents and why the signature matters.

---

## Part 4: JWT Flow We Will Implement (End-to-End)

In this lesson, you will implement the following flow, step by step.

1. Create an authentication endpoint that accepts a username and password.
2. If credentials are valid, generate a JWT token and return it in the response.
3. For protected endpoints, require an `Authorization: Bearer <token>` header.
4. Add a JWT filter that runs before your controller, reads the token, validates it, and sets the authenticated user in Spring Security's context.
5. Test everything in Postman so you can clearly see the difference between requests with and without tokens.

---

## Part 5: Standalone JWT Example (Not Simple CRM Yet)

We will start with a small, standalone example because it helps you learn the JWT flow without dealing with CRM code and database logic at the same time. Once you understand the flow, applying it to `simple-crm` becomes much easier.

### Step 1: Create a New Simple Spring Boot Project

Create a fresh project named `jwt-demo` using Spring Initializr with Spring Web and Spring Security dependencies. Alternatively, you may add the following classes into your existing workspace under a separate package like `com.example.jwtdemo` — the key is that the example stays simple and isolated.

### Step 2: Add Dependencies

Add the JWT library dependencies to `pom.xml`.

> ⚠️ **Note:** We are using `jjwt` version `0.11.5` intentionally in this lesson because its API is clear and beginner-friendly. Version `0.12.x` introduced significant API changes (e.g. `Jwts.parser()` instead of `Jwts.parserBuilder()`, `.subject()` instead of `.setSubject()`). If you look up newer tutorials online, you may see different syntax — this is why.

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-web</artifactId>
</dependency>

<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<dependency>
  <groupId>io.jsonwebtoken</groupId>
  <artifactId>jjwt-api</artifactId>
  <version>0.11.5</version>
</dependency>
<dependency>
  <groupId>io.jsonwebtoken</groupId>
  <artifactId>jjwt-impl</artifactId>
  <version>0.11.5</version>
  <scope>runtime</scope>
</dependency>
<dependency>
  <groupId>io.jsonwebtoken</groupId>
  <artifactId>jjwt-jackson</artifactId>
  <version>0.11.5</version>
  <scope>runtime</scope>
</dependency>
```

### Step 3: Add JWT Settings in `application.properties`

Add a secret key and expiry time.

> ⚠️ **Note:** The JWT secret must be **at least 32 characters long**. If you use a shorter value (like `mysecret`), you will get a `WeakKeyException` at runtime. For training, we store it in `application.properties`. In real projects, secrets should be stored securely using environment variables or a secrets manager.

```properties
jwt.secret=replace-this-with-a-long-random-secret-key-for-training-only
jwt.expiration-ms=3600000
```

### Step 4: Create DTOs for Login Requests and Token Responses

Create a `dto` package and add these two classes.

```java
// LoginRequest.java
public class LoginRequest {
    private String username;
    private String password;

    public LoginRequest() {}

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}
```

```java
// TokenResponse.java
public class TokenResponse {
    private String token;

    public TokenResponse() {}

    public TokenResponse(String token) {
        this.token = token;
    }

    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
}
```

### Step 5: Create a `JwtService` to Generate and Validate Tokens

This class is responsible for creating and validating JWTs. Notice that we are adding the username as the token's subject and adding an expiration timestamp.

> ⚠️ **Note:** You may see a deprecation warning on `SignatureAlgorithm.HS256` when using `jjwt 0.11.5`. This is expected and harmless — the code still works correctly. The warning exists because `0.12.x` replaced this with a different API.

```java
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration-ms}")
    private long jwtExpirationMs;

    private Key getSigningKey() {
        // For HS256, we use a shared secret key.
        // The secret must be at least 32 characters long.
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(String username) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtExpirationMs);

        return Jwts.builder()
                .setSubject(username)            // Who the token is for
                .setIssuedAt(now)                // When token was created
                .setExpiration(expiry)           // When token expires
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractUsername(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }

    public boolean isTokenValid(String token) {
        try {
            // Parsing validates signature and also checks expiration.
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);

            return true;
        } catch (Exception ex) {
            // In production you would log this exception.
            return false;
        }
    }
}
```

### Step 6: Create a Simple Auth Controller That Issues Tokens

This endpoint will accept credentials and return a token. For the standalone demo, we keep user validation simple with in-memory checking. The goal here is to understand the JWT flow, not user storage.

```java
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final JwtService jwtService;

    public AuthController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest request) {

        // TRAINING ONLY: Simple in-memory credential check.
        // In real applications, validate against a database or identity provider.
        if ("user".equals(request.getUsername()) && "password".equals(request.getPassword())) {
            String token = jwtService.generateToken(request.getUsername());
            return new ResponseEntity<>(new TokenResponse(token), HttpStatus.OK);
        }

        // Return 401 Unauthorized if credentials are invalid
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }
}
```

### Step 7: Create a Simple Protected Endpoint

This endpoint will be protected by JWT. Once JWT security is working, calling it without a token should return `401 Unauthorized`, and calling it with a valid token should return `200 OK`.

It is important to notice that the controller itself does not contain any JWT code. In Spring Security, endpoints are protected by the **security configuration** and the **filter chain** — not by annotations on the controller. So even though this looks like a normal controller, it becomes protected because:
1. The request passes through the JWT filter first, and
2. The `SecurityConfig` marks `/api/**` as authenticated.

```java
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/api/hello")
    public String hello() {
        return "Hello! You successfully accessed a protected endpoint using JWT.";
    }
}
```

### Step 8: Create the JWT Authentication Filter

This filter intercepts incoming requests and validates the JWT before the request reaches the controller. Many students find this part overwhelming at first — focus on the **purpose** rather than memorising every line. It is also perfectly acceptable to copy and paste this filter code; it is standard boilerplate used across real Spring Boot applications.

**Mental model of what the filter does:**

1. Look for the `Authorization` header in the format `Bearer <token>`
2. If missing, pass the request along — Spring Security will decide later if the route needs authentication
3. If present, extract and validate the token (signature + expiry)
4. If valid, extract the username and set an authenticated user in Spring Security's `SecurityContext`
5. The controller then receives a request that Spring Security already considers authenticated

```java
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    public JwtAuthFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // If there's no Authorization header, continue the chain.
        // SecurityConfig will decide whether the route requires authentication.
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring("Bearer ".length());

        // Validate token first
        if (jwtService.isTokenValid(token)) {
            String username = jwtService.extractUsername(token);

            // TRAINING ONLY: Empty authorities — keeping the flow simple for learning.
            // In real applications, you would load roles/authorities from the database.
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());

            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // Set authentication into SecurityContext so Spring treats the user as authenticated
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }
}
```

### Step 9: Configure Spring Security to Use the JWT Filter

This configuration tells Spring Security which endpoints are public, which require authentication, and connects the JWT filter into the chain. It is also perfectly acceptable to copy and paste this configuration — it is a standard JWT setup pattern.

Key rules applied here:
- `/auth/login` is public — users must be able to log in before they have a token
- `/api/**` requires authentication — all routes under `/api/` are protected
- `SessionCreationPolicy.STATELESS` — no server-side sessions; every request must carry the token
- JWT filter runs **before** `UsernamePasswordAuthenticationFilter` so authentication is resolved early

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter) {
        this.jwtAuthFilter = jwtAuthFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            // REST APIs disable CSRF when using stateless auth like JWT
            .csrf(csrf -> csrf.disable())

            // Stateless: Spring Security will not create or use sessions
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // Define which routes are public vs protected
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/login").permitAll()
                .requestMatchers("/api/**").authenticated()
                .anyRequest().permitAll()
            )

            // Register JWT filter to run before username/password authentication
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
```

---

## Part 6: Step-by-Step Postman Testing for the Standalone Example

### Step 1: Generate a Token Using `/auth/login`

1. Open Postman and click **New → HTTP Request**.
2. Set the method to **POST**.
3. Enter the URL: `http://localhost:8080/auth/login`
4. Click the **Body** tab, choose **raw**, and select **JSON**.
5. Paste the following JSON:

```json
{
  "username": "user",
  "password": "password"
}
```

6. Click **Send**.
7. You should get `200 OK` with a `token` in the response. Copy the token.

### Step 2: Call the Protected Endpoint Without Token (Expected Failure)

1. Create a new **GET** request to: `http://localhost:8080/api/hello`
2. Click **Send**.
3. You should receive `401 Unauthorized` — expected, because no token was provided.

### Step 3: Call the Protected Endpoint With Token (Expected Success)

1. Open the same GET request.
2. Click the **Headers** tab and add:
   - Key: `Authorization`
   - Value: `Bearer <paste-your-token-here>`
3. Click **Send**.
4. You should now receive `200 OK` and the success message.

If this works, you have successfully implemented the complete JWT flow: **login → token → protected endpoint access**.

---

## Part 7: Applying JWT to Simple CRM

Now that you understand the JWT flow, you will apply it to `simple-crm`. The reason we do it in this order is because CRM has more layers, and learning JWT inside CRM from the start is much harder. At this point you already understand the most important part — how the token is generated and validated.

### Step 1: Add JWT Dependencies and Properties to Simple CRM

Copy the same `jjwt-*` dependencies into CRM's `pom.xml` and add the same `jwt.secret` and `jwt.expiration-ms` settings to CRM's `application.properties`.

### Step 2: Add Auth Endpoint in CRM

Create an `AuthController` under a suitable package (e.g. `auth`). The endpoint should be `POST /auth/login`. For training, use the same simple in-memory credential check so students can focus on the JWT flow.

### Step 3: Add JwtService and JwtAuthFilter in CRM

Copy `JwtService` and `JwtAuthFilter` into the CRM project. Update packages and imports to match the CRM structure.

### Step 4: Update CRM Security Configuration

Update `SecurityConfig` so that:
- `/auth/login` is permitted
- One or two simple CRM endpoints require authentication (start with `GET /customers`, test it, then add `GET /customers/{id}`)
- Endpoints involving JPA relationships should not be included in the demo initially

```java
.authorizeHttpRequests(auth -> auth
    .requestMatchers("/auth/login").permitAll()
    .requestMatchers("/customers").authenticated()
    .requestMatchers("/customers/**").authenticated()
    .anyRequest().permitAll()
)
```

---

## Part 8: Step-by-Step Postman Testing for Simple CRM

### Step 1: Get Token
Send a **POST** to `http://localhost:8080/auth/login` with your CRM credentials. Copy the token.

### Step 2: Call CRM Endpoint Without Token (Expected Failure)
Send a **GET** to `http://localhost:8080/customers`. You should get `401 Unauthorized`.

### Step 3: Call CRM Endpoint With Token (Expected Success)
Add the header `Authorization: Bearer <your-token>` and send again. You should now get `200 OK` with the customer list.

---

## 🧑‍💻 Activity **(20 minutes)**

Independently practise the full JWT flow with the Simple CRM application.

1. Start your Simple CRM application and verify it is running.
2. Use Postman to send a **POST** to `/auth/login` and generate a JWT token.
3. Copy the token from the response.
4. Send a **GET** to `/customers` **without** the `Authorization` header — confirm you get `401 Unauthorized`.
5. Add the header `Authorization: Bearer <your-token>` and send again — confirm `200 OK`.
6. Repeat the same steps for **one additional endpoint** (e.g. `GET /customers/{id}`).

Focus on understanding the flow rather than memorising code. The key insight is: **generate once, use until expiry**.

---

## Key Takeaways

- **JWT** allows REST APIs to remain stateless while still authenticating users reliably
- The server issues a **signed token** during login and validates it on every protected request using a Spring Security filter
- The **JWT filter** sets the authenticated user in Spring Security's `SecurityContext` — the controller never needs to know about JWT
- Once you understand the standalone example, applying JWT to a layered project like `simple-crm` becomes a repeatable process: add JWT generation, add JWT validation filter, update security rules, test in Postman

---

END