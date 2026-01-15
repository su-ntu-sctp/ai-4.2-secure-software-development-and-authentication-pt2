# Module 4 – Lesson 4.2  
# Spring Security Part 2: JWT Authentication & Authorization 

---

## Lesson Overview

In this lesson, you will implement **JWT (JSON Web Token)** authentication in a Spring Boot application so that users can log in once, receive a token, and then use that token to access protected REST endpoints without using server-side sessions. We will begin with a small, standalone example to learn the complete JWT flow (generate token → send token → validate token → access protected endpoint), and then we will apply the same approach to **one or two simple endpoints** in our existing `simple-crm` project so you can see how JWT fits into a real application.

---

## Lesson Duration & Timing Breakdown

This lesson is designed for a **3-hour instructor-led session**. The breakdown below helps both instructors and students understand the expected pace.

- Warm-up & recap of previous lesson: ~10 minutes  
- JWT concepts and mental model: ~35 minutes  
- Standalone JWT example (code + explanation): ~55 minutes  
- Short break / buffer: ~10 minutes  
- JWT filter and security configuration deep explanation: ~35 minutes  
- Applying JWT to Simple CRM: ~30 minutes  
- Hands-on activities: ~20 minutes  
- Wrap-up and Q&A: ~15 minutes  

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

In session-based authentication, the server “remembers” the user by storing session state after login. The client only needs to send a session identifier, and the server uses it to retrieve the session from memory or a session store. In JWT-based authentication, the server does not store a session. Instead, the server issues a token that contains user identity information (claims) and a signature. On every request, the server validates the token signature and expiry; if valid, the server treats the user as authenticated.

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
4. Add a JWT filter that runs before your controller, reads the token, validates it, and sets the authenticated user in Spring Security’s context.  
5. Test everything in Postman so you can clearly see the difference between requests with and without tokens.

---

## Part 5: Standalone JWT Example (Not Simple CRM Yet)

We will start with a small, standalone example because it helps you learn the JWT flow without dealing with CRM code and database logic at the same time. Once you understand the flow, applying it to `simple-crm` becomes much easier.

### Step 1: Create a New Simple Spring Boot Project (or a New Package in an Existing Sandbox)

If you prefer, you can do this in a fresh project named `jwt-demo`. If you want fewer projects, you may also add the following classes into your existing workspace under a separate package like `com.example.jwtdemo`. The key is that the example must stay simple.

### Step 2: Add Dependencies

Add Spring Security and Web (if not already present). Then add a JWT library.

In `pom.xml`, include:

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

Add a secret key and expiry time. For training, we store it in `application.properties`. In real projects, secrets should be stored securely (environment variables, vault, etc.), but we keep it simple here.

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

This class is responsible for creating and validating JWTs. Notice that we are adding the username as the token’s subject and adding an expiration timestamp.

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
        // IMPORTANT: For HS256, we use a shared secret key.
        // The secret must be long enough for the algorithm.
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

This endpoint will accept credentials and return a token. For the standalone demo, we will keep user validation very simple with in-memory checking. The goal is not user storage yet; the goal is to understand the JWT flow.

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

        // TRAINING-ONLY: Very simple credential check.
        // In real applications, you validate against a database or identity provider.
        if ("user".equals(request.getUsername()) && "password".equals(request.getPassword())) {
            String token = jwtService.generateToken(request.getUsername());
            return new ResponseEntity<>(new TokenResponse(token), HttpStatus.OK);
        }

        // Return 401 Unauthorized if credentials are invalid
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }
}
```

### Step 7: Create a Simple Protected Endpoint (Hello Endpoint)

This endpoint will be protected by JWT. Once JWT security is working, calling this endpoint without a token should result in `401 Unauthorized`, and calling it with a valid token should return `200 OK`.

It is important to notice that the controller itself does not contain “JWT code” or any special annotations that say “secure this endpoint”. In Spring Security, endpoints are protected by the **security configuration** and the **security filter chain**. When we later configure Spring Security to require authentication for routes under `/api/**`, Spring Security will block requests to `/api/hello` unless a valid JWT has already been validated by our JWT filter.

So, even though this controller looks like a normal Spring controller, it becomes protected because:
1) the request passes through the JWT filter first, and  
2) the `SecurityConfig` rules mark `/api/**` as authenticated.

Now create the controller exactly as shown below.
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

### Step 8: Create a JWT Authentication Filter

This filter will run for incoming requests, and this is where JWT starts to feel “real” because we are now intercepting requests before they reach the controller. Many students find this part overwhelming at first, so read it slowly and focus on the purpose rather than memorising every line.

Think of the JWT filter as a “security gatekeeper” that checks each request for a token.

Here is the step-by-step mental model of what the filter does:

1. **Look for the `Authorization` header.**  
   Spring Security does not magically know your token. The client must send it. The standard place is the request header:  
   `Authorization: Bearer <token>`

2. **If the header is missing (or does not start with `Bearer `), do not stop the request here.**  
   The filter simply continues the chain. Later, Spring Security will decide whether that route is allowed without authentication. For protected routes, Spring Security will eventually return `401 Unauthorized` because the request is not authenticated.

3. **If the Bearer token exists, extract the token string.**  
   We remove the `Bearer ` prefix and keep only the JWT text.

4. **Validate the token.**  
   Validation means checking that:
   - the token signature is correct (token was not modified), and
   - the token is not expired.

5. **If the token is valid, extract the username from it.**  
   We stored the username as the JWT “subject” when generating the token.

6. **Create an `Authentication` object and store it in Spring Security’s `SecurityContext`.**  
   This is the most important part. Once the `SecurityContext` contains an authenticated user, Spring Security treats the request as authenticated for the rest of the request lifecycle.

After this, the controller does not need to know anything about JWT. It just receives a normal request that Spring Security already considers authenticated.

If this section feels overwhelming, it is completely okay to **copy and paste this filter code**. This filter pattern is standard boilerplate for JWT setup in Spring Security, and understanding it fully often comes gradually with practice.

Now add the filter exactly as shown below.
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
        // The SecurityConfig will decide whether the route is permitted or requires authentication.
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring("Bearer ".length());

        // Validate token first
        if (jwtService.isTokenValid(token)) {
            String username = jwtService.extractUsername(token);

            // TRAINING-ONLY: We are not loading roles/authorities from DB in this demo.
            // We'll set an authenticated user with empty authorities to keep the flow simple.
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

Now we create a `SecurityConfig` that tells Spring Security two big things: **which endpoints are public**, and **which endpoints require authentication**. This is also the place where we connect our JWT filter into Spring Security’s filter chain.

Read this carefully as a simple set of rules:

First, we allow unauthenticated access to `/auth/login`. This is necessary because users must be able to log in and get a token before they can access anything protected.

Next, we require authentication for `/api/**`. This means every route starting with `/api/` becomes protected. So `/api/hello` is protected because it matches `/api/**`. If a request comes in without a valid token, Spring Security will block it.

We also set the session policy to `STATELESS`. This is crucial for JWT. It tells Spring Security: “Do not store user sessions on the server.” Every request must prove authentication using the token.

Finally, we add our JWT filter **before** `UsernamePasswordAuthenticationFilter`. This ordering matters because we want Spring Security to check JWT tokens early, so that by the time authorization rules run, the user is already authenticated (if the token is valid).

If this configuration feels complex, it is perfectly okay to **copy and paste this code**. This is a very common JWT configuration pattern used across real Spring Boot applications.

Now create the configuration exactly as shown below.
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
            // REST APIs typically disable CSRF when using stateless auth mechanisms like JWT
            .csrf(csrf -> csrf.disable())

            // Make the application stateless: Spring Security will not create or use sessions
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // Define which routes are public vs protected
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/login").permitAll()
                .requestMatchers("/api/**").authenticated()
                .anyRequest().permitAll()
            )

            // Register our JWT filter so it runs before username/password authentication
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
```

---

## Part 6A: Step-by-Step Postman Testing for the Standalone Example

The goal here is to make the flow extremely clear. You will first get a token, then use that token to access the protected endpoint.

### Step 1: Generate a Token Using `/auth/login`

1. Open Postman and click **New → HTTP Request**.  
2. Set the method to **POST**.  
3. Enter the URL:  
   `http://localhost:8080/auth/login`  
4. Click the **Body** tab, choose **raw**, and select **JSON**.  
5. Paste the following JSON:

```json
{
  "username": "user",
  "password": "password"
}
```

6. Click **Send**.  
7. If credentials are correct, you should get `200 OK` and a response that contains a `token` value. Copy the token.

### Step 2: Call the Protected Endpoint Without Token (Expected Failure)

1. Create a new request in Postman.  
2. Set method to **GET**.  
3. Enter the URL:  
   `http://localhost:8080/api/hello`  
4. Click **Send**.  
5. You should receive `401 Unauthorized`. This is expected because you did not provide the token.

### Step 3: Call the Protected Endpoint With Token (Expected Success)

1. Open the same request (GET `/api/hello`).  
2. Click the **Headers** tab.  
3. Add a new header:

- Key: `Authorization`  
- Value: `Bearer <paste-your-token-here>`

For example:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

4. Click **Send** again.  
5. You should now receive `200 OK` and the success message from the controller.

If this works, you have successfully implemented the complete JWT flow: login → token → protected endpoint access.

---

## Part 7: Applying JWT to Simple CRM (One or Two Simple Endpoints Only)

Now that you understand the JWT flow, you will apply the same idea to the `simple-crm` project. The reason we do it in this order is because CRM has more layers (controller/service/repository), and learning JWT inside CRM from the start is much harder for learners. At this point, you already understand the most important part: how the token is generated and how the server validates it for protected routes.

### Step 1: Add JWT Dependencies and Properties to Simple CRM

Copy the same JWT dependencies (`jjwt-*`) into the CRM’s `pom.xml` and add the same `jwt.secret` and `jwt.expiration-ms` settings into CRM’s `application.properties`. Keep the secret consistent within the CRM project so tokens can be verified.

### Step 2: Add Auth Endpoint in CRM

Create an `AuthController` in the CRM project under a suitable package like `com.skillsunion.simplecrm.auth` (or similar). The endpoint should be:

```
POST /auth/login
```

For training, you can use an in-memory credential check first so students can focus on JWT flow. If your CRM already has a user system, you would validate against it, but we keep it simple at this stage.

### Step 3: Add JWT Service and Filter in CRM

Copy the `JwtService` and `JwtAuthFilter` into the CRM project. Ensure that packages and imports are updated to match CRM structure. The filter must run for protected routes and should not block the login endpoint.

### Step 4: Update CRM Security Configuration

Update the CRM `SecurityConfig` so that:

- `/auth/login` is permitted  
- One or two simple CRM endpoints require authentication (for example, `GET /customers` and `GET /customers/{id}`)  
- Endpoints involving JPA relationships must not be included in the demo  

A beginner-friendly approach is to start by securing only `GET /customers` first, test it, and then secure `GET /customers/{id}` next.

Example configuration (adjust as needed for your CRM routes):

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

The CRM testing flow is the same as the standalone example, but now you are calling CRM endpoints.

### Step 1: Get Token

1. In Postman, send a **POST** request to:  
   `http://localhost:8080/auth/login`  
2. Use the same JSON credentials that your CRM login endpoint expects.  
3. Copy the token from the response.

### Step 2: Call CRM Endpoint Without Token (Expected Failure)

1. Create a **GET** request to:  
   `http://localhost:8080/customers`  
2. Click **Send**.  
3. You should get `401 Unauthorized` because it is now protected.

### Step 3: Call CRM Endpoint With Token (Expected Success)

1. Add the header:  
   `Authorization: Bearer <your-token>`  
2. Click **Send** again.  
3. You should now receive `200 OK` and the CRM response (list of customers).

---


## Hands-On Activity

In this activity, **you will independently practise using JWT tokens** with the Simple CRM application. The goal is to reinforce the full JWT flow by executing each step yourself, from token generation to accessing protected endpoints.

### Your Task

1. Start your Simple CRM application and ensure it is running successfully.
2. Use Postman to send a **POST** request to the CRM login endpoint:
   ```
   POST /auth/login
   ```
   Provide the required username and password in the request body and generate your own JWT token.
3. Copy the JWT token from the response.
4. Create a **GET** request for a simple protected CRM endpoint, such as:
   ```
   GET /customers
   ```
5. First, send the request **without** the `Authorization` header and observe the `401 Unauthorized` response.
6. Next, add the following header to your request:
   ```
   Authorization: Bearer <your-jwt-token>
   ```
7. Send the request again and confirm that you now receive a successful response.
8. Repeat the same steps for **one additional simple CRM endpoint** (for example, `GET /customers/{id}`), ensuring you use the JWT token correctly each time.

As you complete this activity, focus on understanding the flow rather than memorising code. You should clearly see how generating a token once allows you to access protected endpoints until the token expires.


---

## Key Takeaways

JWT allows REST APIs to remain stateless while still authenticating users reliably. The critical implementation idea is that the server issues a signed token during login, and then the server validates that token for every protected request using a Spring Security filter. Once you understand the standalone example, applying JWT to a layered project like `simple-crm` becomes a repeatable process: add JWT generation, add JWT validation filter, update security rules, and test in Postman using the Bearer token header.

---
