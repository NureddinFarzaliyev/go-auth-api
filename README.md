# Go Auth API

User Authentication API built with Go and MongoDB.

![tech stack](https://skills-icons.vercel.app/api/icons?i=go,mongodb)

| Endpoint            | Description                                             |
| ------------------- | ------------------------------------------------------- |
| `/v1/auth/register` | Allows users to create an account, stores it in memory  |
| `/v1/auth/login`    | Logs in the user and returns CSRF token in memory       |
| `/v1/auth/logout`   | Removes tokens from memory                              |
| `/v1/protected`     | Protected route that only logged in users can access    |
| `/v2/auth/register` | Allows users to create an account, stores it in MongoDB |
| `/v2/auth/login`    | Logs in the user and returns CSRF token in MongoDB      |
| `/v2/auth/logout`   | Removes tokens from MongoDB                             |
| `/v2/protected`     | Protected route that only logged in users can access    |
