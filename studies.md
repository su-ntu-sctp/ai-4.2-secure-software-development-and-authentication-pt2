# Self Studies: Spring Security Part 2 — JWT Authentication & Authorization

## Overview

This lesson introduces JWT — one of the most widely used authentication mechanisms in modern REST APIs. JWT is conceptually different from Basic Auth and requires understanding a new mental model. The self-study materials below will help you arrive with a clear picture of how tokens work so you can follow the code-along confidently. Pay close attention to the filter — it is the most important and most commonly misunderstood part.

**Estimated Prep Time:** 60–80 minutes

---

## Task 1: Spring Boot JWT Authentication Tutorial

This video covers the complete JWT implementation — token generation, validation, the JWT filter, and securing REST endpoints with Spring Security. It maps directly to Parts 5 to 8 of the lesson.

**Watch:** Spring Boot JWT Authentication Tutorial
🎬 https://www.youtube.com/watch?v=KxqlJblhzfI

**Then read:** Lesson 4.2 — Parts 1 to 5

**Guiding Questions:**
- What is the difference between session-based and token-based (stateless) authentication?
- What are the three parts of a JWT and what does each contain?
- What does the JWT filter do and at what point in the request lifecycle does it run?
- Why does `SessionCreationPolicy.STATELESS` matter for JWT?
- Why does the controller not need any JWT-specific code?

---

## Task 2: Read — JWT Flow and Security Configuration

This is a read-only task to consolidate your understanding of the end-to-end JWT flow before the code-along.

**Read:** Lesson 4.2 — Parts 3, 4, and the `SecurityConfig` section of Part 5

**Guiding Questions:**
- What happens step by step when a user sends a login request and gets a token?
- What happens step by step when a user sends a request with a Bearer token?
- Why must `/auth/login` be permitted while `/api/**` is authenticated?
- What does `addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)` mean?

---

## Task 3: Prepare Your Environment

Before class, make sure both your environment and `simple-crm` project are ready — the second half of the lesson applies JWT directly to CRM.

**Checklist:**
- [ ] `simple-crm` runs without errors on `mvn spring-boot:run`
- [ ] PostgreSQL is running and connected
- [ ] Spring Security from Lesson 4.1 is still in place — JWT builds on top of it
- [ ] Postman is installed and you are comfortable sending POST requests with a JSON body

---

## Active Engagement Strategies

- As you watch the video, draw the JWT flow on paper: client → login endpoint → token → protected endpoint → filter → SecurityContext → controller
- After watching, try to write the `JwtService` class from memory — just the method signatures and key concepts, not every line
- Think about the `simple-crm` project: which endpoints would you protect with JWT in a real CRM application?

---

## Additional Reading Material

- [JWT Introduction — jwt.io](https://jwt.io/introduction)
- [Spring Security JWT Tutorial — Baeldung](https://www.baeldung.com/spring-security-oauth-jwt)
- [OncePerRequestFilter Explained — Baeldung](https://www.baeldung.com/spring-onceperrequestfilter)
- [Stateless Authentication — Baeldung](https://www.baeldung.com/spring-security-session)