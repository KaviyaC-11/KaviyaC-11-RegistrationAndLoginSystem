# Secure Authentication System (Spring Boot + JWT + OTP)

A full-stack authentication system built using **Spring Boot (Java)** and **HTML, CSS, JavaScript**.  
This project implements **secure user registration, login, email OTP verification, password reset, and account deletion** using industry-standard practices such as **JWT authentication** and **password hashing**.

------------------------------------------------------------------------------

## Features

- User Registration with **Email OTP Verification**
- Secure Login using **JWT (JSON Web Token)**
- Forgot Password & Reset Password using OTP
- **JWT-protected APIs** with custom authentication filter
- Account Deletion (Authenticated users only)
- Automatic logout on unauthorized access
- Clean and responsive frontend UI
- OTP resend with cooldown and user-friendly OTP input UX

------------------------------------------------------------------------------

## Project Architecture

```
Frontend (HTML, CSS, JavaScript)
|
|  REST APIs (Fetch)
v
Spring Boot Backend
|
├── Controllers
├── JWT Filter & Utilities
├── OTP & Email Service
└── Data Access Layer
|
v
PostgreSQL Database
```

------------------------------------------------------------------------------

## Tech Stack

### Frontend
- HTML  
- CSS  
- JavaScript (Vanilla)

### Backend
- Java  
- Spring Boot  
- REST APIs  
- JWT (JSON Web Token)

### Database & Tools
- PostgreSQL  
- Maven  
- Email SMTP (OTP delivery)

------------------------------------------------------------------------------

## Authentication Flow

### 1 Registration
- User registers with email and password
- OTP is sent to the registered email
- User verifies OTP to activate the account

### 2 Login
- User logs in with verified credentials
- Backend generates a **JWT token**
- Token is stored on the client and used for protected requests

### 3️ Forgot / Reset Password
- User requests password reset
- OTP is sent to email
- OTP is verified and password is securely updated

### 4️ Account Deletion
- Only authenticated users can delete their account
- Request is validated using JWT token

------------------------------------------------------------------------------

## Security Implementation

- Passwords are **hashed** before storing in the database
- JWT tokens are validated using a **custom filter**
- Protected routes reject unauthorized requests
- CORS configured for frontend-backend communication
- Session handling with automatic logout on `401 Unauthorized`

------------------------------------------------------------------------------

## Project Structure

```
├── secureauth/
│ └── src/main/java/com/secureauth/secureauth/
│ ├── config/
│ │ └── CorsConfig.java
│ ├── controller/
│ │ ├── AuthController.java
│ │ └── TestController.java
│ ├── dao/
│ │ └── UserDAO.java
│ ├── dto/
│ │ └── ResetPasswordRequest.java
│ ├── model/
│ │ ├── ApiResponse.java
│ │ └── User.java
│ ├── security/
│ │ ├── FilterConfig.java
│ │ └── JwtFilter.java
│ ├── service/
│ │ └── EmailService.java
│ ├── util/
│ │ ├── JwtUtil.java
│ │ ├── OTPUtil.java
│ │ └── PasswordUtil.java
│ └── SecureauthApplication.java
|  └── src/main/resources
|     └── application.properties
├── pom.xml
├── README.md

````

------------------------------------------------------------------------------

### Setup Instructions

### Prerequisites
- Java 11 or above
- Maven
- PostgreSQL
- Email SMTP credentials

### Backend Setup

1. Clone the repository
   ```bash
   git clone https://github.com/your-username/your-repo-name.git
````

2. Configure `application.properties`

   ```
   spring.datasource.url=jdbc:postgresql://localhost:5432/your_db
   spring.datasource.username=your_username
   spring.datasource.password=your_password

   spring.mail.username=your_email
   spring.mail.password=your_email_app_password
   ```

3. Run the application

   ```bash
   mvn spring-boot:run
   ```

 ### Frontend Setup

* Open `index.html` in live server in vscode or browser.
* Ensure backend is running on `http://localhost:8080`

------------------------------------------------------------------------------

### Author

Kaviya C
GitHub: [https://github.com/KaviyaC-11]
LinkedIn: [https://www.linkedin.com/in/kaviya-c-386b2729b]

------------------------------------------------------------------------------

⭐ If you find this project useful, feel free to star the repository!

------------------------------------------------------------------------------
