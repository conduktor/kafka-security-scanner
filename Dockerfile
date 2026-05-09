# Multi-stage build: build with Gradle + JDK 25, run on slim JRE 25.
# Java 25 preview features required at both build and run time.

FROM eclipse-temurin:25_36-jdk AS build
WORKDIR /src

ARG GRADLE_VERSION=9.5.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && curl -fsSL "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" -o /tmp/gradle.zip \
    && unzip -q /tmp/gradle.zip -d /opt \
    && ln -s "/opt/gradle-${GRADLE_VERSION}/bin/gradle" /usr/local/bin/gradle \
    && rm /tmp/gradle.zip \
    && apt-get purge -y curl unzip \
    && rm -rf /var/lib/apt/lists/*

COPY build.gradle settings.gradle gradle.properties ./
COPY config/ config/
COPY src/ src/
COPY policies/ policies/

RUN gradle --no-daemon installDist -x test -x check

# ── Runtime stage ────────────────────────────────────────────
FROM eclipse-temurin:25_36-jre

LABEL org.opencontainers.image.title="kafka-security-scanner"
LABEL org.opencontainers.image.description="Scan Apache Kafka clusters for security misconfigurations."
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/conduktor/kafka-security-scanner"

WORKDIR /opt/kafka-security-scanner

COPY --from=build /src/build/install/kafka-security-scanner/ ./
COPY --from=build /src/policies/ ./policies/

# Run as non-root.
RUN groupadd -r scanner && useradd -r -g scanner scanner \
    && chown -R scanner:scanner /opt/kafka-security-scanner
USER scanner

ENV PATH="/opt/kafka-security-scanner/bin:${PATH}"
ENTRYPOINT ["kafka-security-scanner"]
CMD ["--help"]
