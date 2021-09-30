# Spring Authorization Server example with JDK17

> Project developed on a Windows 10 64-bit machine with OpenJDK 17 installed.

This project is an implementation of [Spring Authorization Server](https://github.com/spring-projects/spring-authorization-server),
with a specific focus on building with JDK17 and running with JRE17.

As of **2021-09-30**, Gradle GA does not support JDK17, however, Gradle nightly releases have early support, hence
this project uses a nightly release of Gradle.

## Prerequisites

- GNU Make
- JDK17

## Getting started

Launch authorization server: 

```bash
make start-authorization-server
```

To verify, it is up and running, navigate to `http://localhost:9000`

## References

- [Gradle nightly releases](https://gradle.org/release-nightly/)