# OWASP Insecure Application

> **WARNING: This application is intentionally vulnerable and contains numerous security flaws.**
> It is designed **only** for security training, static-analysis benchmarking, and controlled
> penetration-testing exercises. **Do not deploy this code in production or expose it to the
> internet.**

This repository is a deliberately insecure multi-language web application that demonstrates
many of the [OWASP Top 10 (2021)](https://owasp.org/Top10/) and additional common
vulnerability classes. The code is written so that static-analysis tools such as **Semgrep**
and **CodeQL** can detect the weaknesses.

## Goals

- Provide a benchmark target for SAST scanners.
- Demonstrate how NOT to write secure code.
- Help developers learn secure coding by comparing vulnerable implementations with secure fixes.

## Languages / Frameworks Included

- Java (Spring Boot)
- Python (Flask)
- JavaScript / TypeScript (Node.js / Express)

## Running

See the individual module READMEs (if present) or build files. Remember: **run only in an
isolated, non-production environment.**

## License

This project is provided as-is for educational and research purposes.
