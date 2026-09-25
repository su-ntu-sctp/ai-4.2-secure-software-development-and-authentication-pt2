# Module 4 – Lesson 4.2
# Spring Security Part 2: JWT Authentication & Authorization

---

## Lesson Overview

In this lesson, you will implement **JWT (JSON Web Token)** authentication in the `simple-crm` project so that users can log in once, receive a token, and then use that token to access protected REST endpoints without using server-side sessions. You will build on the `simple-crm` project from Lesson 4.1 and walk through the complete JWT flow: generate token → send token → validate token → access protected endpoint.

---

## Lesson Objectives

By the end of this lesson, learners will be able to:

1. **Explain** how JWT supports stateless authentication in REST APIs
2. **Implement** JWT token generation and validation in Spring Security
3. **Secure** the Simple CRM endpoints using JWT
4. **Test** the JWT flow end-to-end in Postman

---

## Prerequisites

You should already be comfortable with Spring Boot REST controllers, Spring Security fundamentals from Lesson 4.1 (basic auth, in-memory users, route protection), and the structure of the `simple-crm` project (controller → service → repository).

> 📦 **Starting point:** Use the `simple-crm` working copy shared by your instructor. Unzip it, open it in VS Code, and update `spring.datasource.password` in `application.properties` to your own PostgreSQL password.

---

## 📖 Self Reading — Parts 1 to 4

> These sections are covered in the slides during class. Read through them after the session to reinforce your understanding.

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

> 📖 **End of Self Reading — Parts 1 to 4**

---

## Part 5: Implementing JWT in Simple CRM

### Step 0: Pre-flight Check

Before writing any JWT code, confirm your starting project works.

1. Make sure PostgreSQL is running and the `simple_crm` database exists.
2. Start the `simple-crm` application.
3. In Postman, send a **GET** to `http://localhost:8080/customers` using the **Authorization** tab → **Basic Auth** → username `user`, password `password`.
4. You should get `200 OK` with the customer list.

> ⚠️ Do not continue until this works. If the app does not start here, the problem is in your setup (database, password), not in JWT.

### Step 1: Add JWT Dependencies

Add the JWT library dependencies to `pom.xml`, inside `<dependencies>`.

> ⚠️ **Note:** We are using `jjwt` version `0.11.5` intentionally in this lesson because its API is clear and beginner-friendly. Version `0.12.x` introduced significant API changes (e.g. `Jwts.parser()` instead of `Jwts.parserBuilder()`, `.subject()` instead of `.setSubject()`). If you look up newer tutorials online, you may see different syntax — this is why.

```xml
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

> 📖 **Self Reading — What each dependency does:**
> - `jjwt-api` — the core JWT library. Provides the API (interfaces and classes) you use in your code to build and parse tokens. This is the only jar your code compiles against.
> - `jjwt-impl` — the runtime implementation of the JWT API.
> - `jjwt-jackson` — handles JSON serialisation and deserialisation of JWT claims using the Jackson library. 

### Step 2: Add JWT Settings in `application.properties`

Add a secret key and expiry time at the end of `application.properties`.

> 📖 **What is the JWT secret and why do we need it?**
> The JWT secret is a password that only the server knows. `JwtService` uses it to **sign** every token it creates and to **check** every token that comes back. If someone creates a fake token or changes a real one, the signature won't match the secret, and the request is rejected. The value used here is a placeholder sentence for training; any text longer than 32 characters works.

> ⚠️ **Note:** The JWT secret must be **at least 32 characters long**. If you use a shorter value (like `mysecret`), you will get a `WeakKeyException` at runtime. For training, we store it in `application.properties`. In real projects, secrets must be stored securely — never in source code.

```properties
jwt.secret=replace-this-with-a-long-random-secret-key-for-training-only
jwt.expiration-ms=3600000
```

> ⚠️ **Note:** VS Code will show a yellow warning on `jwt.secret` and `jwt.expiration-ms` saying they are unknown properties. This is harmless — custom properties you define yourself always show this warning. Spring Boot resolves them correctly at runtime via `@Value`.

> ⚠️ **Note:** The property name `jwt.expiration-ms` uses a **hyphen** between `expiration` and `ms`. Your `@Value` annotation in `JwtService` must match exactly: `@Value("${jwt.expiration-ms}")`. Using a dot instead of a hyphen (`jwt.expiration.ms`) is a common mistake that causes a `PlaceholderResolutionException` startup error.

> 📖 **Self Reading — Secret keys in real projects:**
> In production, the JWT secret is never stored in `application.properties` because that file is committed to version control (Git), making the secret publicly visible. Instead, the real-world approach is:
>
> - **Generate** the secret using OpenSSL in the terminal: `openssl rand -base64 32`. This is the standard tool used by most backend developers — it is built into Linux and Mac and available on Windows via Git Bash. Never invent a secret by hand or use an online generator, as the value may pass through a third-party server.
> - **Store** the secret in an environment variable on the server (e.g. `JWT_SECRET=...`) or in a cloud Secrets Manager such as AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager. These are purpose-built secure vaults — not databases — with encryption, access controls, and audit logs.
> - **Reference** it in `application.properties` as `jwt.secret=${JWT_SECRET}` so Spring injects it at runtime from the environment.
> - The secret is **never** stored in a database. The database holds application data (customers, users, orders). The secret key is server configuration — it belongs to the infrastructure layer, not the data layer. Mixing them creates a security risk and a chicken-and-egg startup problem.

> 📖 **How the secret key is used:**
> When a token is created, `JwtService` uses the secret key together with the token's header and payload to calculate a **signature**, and adds that signature to the token. The secret key itself is never put inside the token. When a token comes back with a request, `JwtService` uses the same secret key to calculate the signature again from the token's header and payload, and compares it with the signature in the token. If they match, the token is real and unchanged. If they don't match, the token was changed or faked, and it is rejected.

### Step 3: Create the `auth` and `security` Packages

Under `src/main/java/sg/edu/ntu/simple_crm`, create two new packages:

- `sg.edu.ntu.simple_crm.auth` — for `AuthController` and the two DTOs
- `sg.edu.ntu.simple_crm.security` — for `JwtService` and `JwtAuthFilter`

When you finish this lesson, your new and changed files will be:

```
sg/edu/ntu/simple_crm/
├── auth/
│   ├── AuthController.java      (new)
│   ├── LoginRequest.java        (new)
│   └── TokenResponse.java       (new)
├── security/
│   ├── JwtService.java          (new)
│   └── JwtAuthFilter.java       (new)
└── config/
    ├── AppConfig.java           (new)
    └── SecurityConfig.java      (updated)
```

### Step 4: Create DTOs for Login Requests and Token Responses

Create these two classes in the `auth` package. `simple-crm` already uses Lombok, so the getters, setters and constructors are generated for us.

> 📖 **Self Reading — What these DTOs are for:**
> `LoginRequest` captures the username and password sent by the client in the HTTP request body when calling `/auth/login`. `TokenResponse` wraps the generated JWT token so it is returned to the client as a clean, structured JSON response. Using DTOs here rather than raw strings keeps the API contract explicit — if you need to add fields later (such as token type or expiry time), you extend the DTO without changing the controller signature. This is standard practice in production Spring Boot APIs.

```java
// LoginRequest.java
package sg.edu.ntu.simple_crm.auth;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class LoginRequest {
    private String username;
    private String password;
}
```

```java
// TokenResponse.java
package sg.edu.ntu.simple_crm.auth;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenResponse {
    private String token;
}
```

> ⚠️ **The JSON key must match the field name exactly.** Postman sends `"username"`, so the field must be `username` (all lowercase). If you type `userName` with a capital N, Spring cannot match it, the username arrives empty, and login fails with `401 Unauthorized` even though the password is correct. This is a very common mistake.

### Step 5: Create `JwtService` to Generate and Validate Tokens

Create this class in the `security` package. It is responsible for creating and validating JWTs. Notice that we are adding the username as the token's subject and adding an expiration timestamp.

>

```java
package sg.edu.ntu.simple_crm.security;

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
        // Converts the secret text into a key used to sign and check tokens
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
        // parseClaimsJws validates the signature first, then decodes the payload.
        // If the token was tampered with, it throws an exception before reaching getSubject().
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

> 📖 **What each part of `JwtService` does:**
>
> 1. **The two settings (`@Value`):** read `jwt.secret` and `jwt.expiration-ms` from `application.properties`.
> 2. **`getSigningKey()`:** turns the secret text into a key that the JWT library can use. The other methods call it when they need to sign or check a token.
> 3. **`generateToken(username)`:** creates a new token.
>    - `setSubject(username)` puts the username inside the token.
>    - `setIssuedAt(now)` records when the token was created.
>    - `setExpiration(expiry)` records when the token expires (1 hour later).
>    - `signWith(...)` signs the token with the secret key.
>    - `compact()` turns it into the final token string.
>
>    Called by `AuthController` when the user logs in.
> 4. **`isTokenValid(token)`:** checks a token. It opens the token using the secret key. If the signature is wrong or the token has expired, it returns **false**; otherwise it returns **true**. Called by `JwtAuthFilter` on every request.
> 5. **`extractUsername(token)`:** opens the token and returns the username inside it. Called by `JwtAuthFilter` after the token is confirmed valid.
>
> **In one line:** `JwtService` does three jobs: it creates tokens, checks tokens, and reads the username from tokens.

### Step 6: Create the JWT Authentication Filter

Create `JwtAuthFilter` in the `security` package. This filter intercepts incoming requests and validates the JWT before the request reaches the controller. Focus on the **purpose** rather than memorising every line — this is standard boilerplate used across real Spring Boot applications and it is perfectly acceptable to copy and paste it.

**Mental model of what the filter does:**

1. Look for the `Authorization` header in the format `Bearer <token>`
2. If missing, pass the request along — Spring Security will decide later if the route needs authentication
3. If present, extract and validate the token (signature + expiry)
4. If valid, extract the username and set an authenticated user in Spring Security's `SecurityContext`
5. The controller then receives a request that Spring Security already considers authenticated

```java
package sg.edu.ntu.simple_crm.security;

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

        // If there is no Authorization header, continue the chain.
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
            // In real applications, you would load roles/authorities for this user.
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

> 📖 **What each part of `JwtAuthFilter` does:**
>
> 1. **`@Component` and `extends OncePerRequestFilter`:** `@Component` tells Spring to create this filter automatically. `OncePerRequestFilter` means it runs **once for every request** that comes into the app.
> 2. **The constructor:** the filter needs `JwtService` to check tokens, so Spring passes it in here.
> 3. **`doFilterInternal()`:** the main method, which runs on every request.
>    - **Read the header:** `request.getHeader(...)` gets the `Authorization` header.
>    - **No token? Let it pass:** if the header is missing or doesn't start with `Bearer `, the filter does nothing and passes the request on. `SecurityConfig` decides later whether to block it.
>    - **Take out the token:** `substring(...)` removes the word `Bearer ` so only the token is left.
>    - **Check the token and mark the user as logged in:** it asks `JwtService` whether the token is valid. If it is, it gets the username, creates an "authenticated" object for that user (`Collections.emptyList()` means no roles for now), and saves it in the **`SecurityContext`**. This is how Spring knows "this user is logged in" for this request.
>    - **Continue:** the last line, `filterChain.doFilter(...)`, passes the request on to the next step and eventually to the controller.
>
> **In one line:** the filter checks every request; if it has a valid token, the user is marked as logged in.

### Step 7: Create `AppConfig` to Expose `AuthenticationManager`

Create `AppConfig.java` in the existing `config` package. This class exposes the `AuthenticationManager` bean so that `AuthController` can inject it.

> ⚠️ **Why a separate class?** Keep the `AuthenticationManager` bean out of `SecurityConfig`. Keeping it in its own `AppConfig` class keeps `SecurityConfig` focused on the filter chain and avoids circular-dependency errors as the security setup grows.

```java
package sg.edu.ntu.simple_crm.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;

@Configuration
public class AppConfig {

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
```

> 📖 **Why do we need `AppConfig`?**
> `AuthController` needs the **`AuthenticationManager`** to check the username and password at login. Spring Security builds the `AuthenticationManager` on its own, but it doesn't make it available for other classes to use. `AppConfig` has one job: it **makes the `AuthenticationManager` available** so `AuthController` can use it. The `AuthenticationManager` then checks the login using the users and the password encoder from `SecurityConfig`.
>
> **In one line:** `AppConfig` gives `AuthController` the tool it needs to check the username and password.

### Step 8: Create the Auth Controller

Create `AuthController` in the `auth` package. This endpoint accepts credentials and returns a JWT token. It delegates credential validation to Spring Security's `AuthenticationManager`, which checks the username and password against the in-memory users you already defined in `SecurityConfig` in Lesson 4.1.

> ℹ️ **Why `AuthenticationManager` and not a manual string check?** `AuthenticationManager` is Spring Security's single entry point for authentication — it uses your configured `UserDetailsService` and `PasswordEncoder`. Wiring through it means your login endpoint stays consistent with the rest of Spring Security regardless of how users are stored (in-memory, database, LDAP). This is the pattern you will see in every production Spring Boot application.

```java
package sg.edu.ntu.simple_crm.auth;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import sg.edu.ntu.simple_crm.security.JwtService;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public AuthController(AuthenticationManager authenticationManager, JwtService jwtService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest request) {
        try {
            // Delegate credential validation to Spring Security
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            // If authentication succeeds, generate and return a token
            String token = jwtService.generateToken(request.getUsername());
            return ResponseEntity.ok(new TokenResponse(token));

        } catch (BadCredentialsException e) {
            // Return 401 Unauthorized if credentials are invalid
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
```

> 📖 **What `AuthController` does, in order:**
> 1. The user sends a username and password to `POST /auth/login`. Spring puts them into a `LoginRequest`.
> 2. `authenticationManager.authenticate(...)` checks whether the username and password are correct, using the users in `SecurityConfig`.
> 3. **If they're wrong**, it throws `BadCredentialsException`, and the `catch` block returns **401 Unauthorized**.
> 4. **If they're correct**, `jwtService.generateToken(username)` creates the token.
> 5. The token is put into a `TokenResponse` and returned with **200 OK**.
>
> **In one line:** `AuthController` checks the login, and if it's correct, gives back a token.

### Step 9: Update `SecurityConfig`

Open the existing `SecurityConfig.java` in the `config` package and replace its contents with the version below.

**What changes from Lesson 4.1:**
- A constructor injects `JwtAuthFilter`
- The role-based `requestMatchers` rules and `httpBasic()` are removed
- `/auth/login` is public; every other request requires authentication
- Sessions are set to `STATELESS`
- The JWT filter is registered before `UsernamePasswordAuthenticationFilter`

**What stays the same:** the `passwordEncoder()` bean and the three in-memory users (`user`, `admin`, `manager`) are unchanged. All three can log in via `/auth/login`.

> ℹ️ **Imports:** after the edit, the `HttpMethod` and `Customizer` imports from Lesson 4.1 are no longer used. Delete them. They cause no errors, but VS Code will flag them as unused.

> ℹ️ **Where did the roles go?** Our token only carries the username, and the filter sets empty authorities. If we kept the 4.1 rules like `hasRole("ADMIN")`, every request would be rejected with `403`, even with a valid token. So for this lesson, any logged-in user can access all `/customers` endpoints. Carrying roles inside the JWT is a later step.

> ℹ️ **Note on `@EnableWebSecurity`:** We keep this annotation because it is already in your 4.1 code, but it is not required in Spring Boot. The `SecurityFilterChain` bean is picked up automatically. You will see it in older codebases and online tutorials; modern Spring Boot projects often omit it.

> ⚠️ **Constructor rule:** `SecurityConfig` must only inject `JwtAuthFilter` in its constructor. If GitHub Copilot adds `AuthController` or `AuthenticationManager` as a constructor parameter, remove it — that causes a circular dependency error at startup.

```java
package sg.edu.ntu.simple_crm.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import sg.edu.ntu.simple_crm.security.JwtAuthFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;

    // Only JwtAuthFilter is injected here.
    public SecurityConfig(JwtAuthFilter jwtAuthFilter) {
        this.jwtAuthFilter = jwtAuthFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            // REST APIs using stateless JWT auth do not need CSRF protection.
            // CSRF is designed for browser-based session flows; since we never issue
            // a session cookie, there is nothing for a cross-site request to hijack.
            .csrf(csrf -> csrf.disable())

            // Stateless: Spring Security will not create or use sessions.
            // Every request must carry a valid JWT token.
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // /auth/login is public; everything else needs a valid token
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/login").permitAll()
                .anyRequest().authenticated()
            )

            // Register JWT filter to run before username/password authentication
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // Unchanged from Lesson 4.1
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Unchanged from Lesson 4.1
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder.encode("password"))
                .roles("USER")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("admin123"))
                .roles("ADMIN")
                .build();

        UserDetails manager = User.builder()
                .username("manager")
                .password(passwordEncoder.encode("manager123"))
                .roles("MANAGER")
                .build();

        return new InMemoryUserDetailsManager(user, admin, manager);
    }
}
```

> ℹ️ **Notice: `CustomerController` has not changed at all.** The controller contains no JWT code. In Spring Security, endpoints are protected by the **security configuration** and the **filter chain**, not by code inside the controller. The `/customers` endpoints are now protected because:
> 1. Every request passes through `JwtAuthFilter` first, and
> 2. `SecurityConfig` requires authentication for every route except `/auth/login`.

Restart the application and confirm it starts without errors.

---

## Part 6: Step-by-Step Postman Testing

> ⚠️ **Important:** Remove the Basic Auth you used in Step 0. In your Postman request, open the **Authorization** tab and set it to **No Auth**. From now on, we only use the token.

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

### Step 2: Call a CRM Endpoint Without Token (Expected Failure)

1. Create a new **GET** request to: `http://localhost:8080/customers`
2. Make sure the Authorization tab is set to **No Auth** and no `Authorization` header is present.
3. Click **Send**.
4. You should receive `403 Forbidden` — expected, because no token was provided.

> ℹ️ **Why 403 and not 401?** In Lesson 4.1, a request without credentials returned `401 Unauthorized`. That was because `httpBasic()` tells Spring Security to reply with a login challenge (`401`). We removed `httpBasic()`, so Spring Security now uses its default response for unauthenticated requests, which is `403 Forbidden`. Either way, the request is blocked.
>
> 📖 **FYI only — not implemented in this lesson:** Production APIs often configure a custom "authentication entry point" so that a missing or invalid token returns `401` instead of `403`. You will see this in real projects.

### Step 3: Call a CRM Endpoint With Token (Expected Success)

1. Open the same GET request.
2. Click the **Headers** tab and add:
   - Key: `Authorization`
   - Value: `Bearer <paste-your-token-here>`
3. Click **Send**.
4. You should now receive `200 OK` and the customer list.

> ⚠️ **Postman Bearer Token warning:** Postman has two ways to attach a token. If you use the **Authorization tab** and select "Bearer Token", paste **only the raw token** — no `Bearer` prefix. Postman adds the word `Bearer` automatically. If you type `Bearer eyJ...` in that field, Postman sends `Bearer Bearer eyJ...`, the token is rejected, and you get `403 Forbidden`. To avoid confusion, always use the **Headers tab** for class — add `Authorization` as the key and `Bearer <token>` as the value. This is explicit, unambiguous, and shows exactly what is sent over HTTP.

If this works, you have successfully implemented the complete JWT flow: **login → token → protected endpoint access**.

---

## Key Takeaways

- **JWT** allows REST APIs to remain stateless while still authenticating users reliably
- The server issues a **signed token** during login and validates it on every protected request using a Spring Security filter
- The **JWT filter** sets the authenticated user in Spring Security's `SecurityContext` — the controller never needs to know about JWT
- `AuthenticationManager` is Spring Security's single entry point for credential validation — always wire through it, never check credentials manually
- The `AuthenticationManager` bean lives in a separate `AppConfig` class, and the `SecurityConfig` constructor only injects `JwtAuthFilter`
- Our token currently carries only the username, so role rules from Lesson 4.1 are removed for now — any logged-in user can access the CRM endpoints

---

END