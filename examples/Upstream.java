/*
QUICK SINGLE-FILE SETUP

Prerequisites:
- Unix/macOS/Linux with Bash. For Windows, use Git Bash or WSL.
- Java 17+, [Maven](https://maven.apache.org/install.html).

# Decode and extract pom.xml (includes Spring Boot 3.5.4 + Jackson 2.19.2)
base64 -d <<'EOF' | gzip -d > pom.xml || { echo "base64 decode failed"; exit 1; }
H4sIAGxd8mgCA51UUW+bMBB+z69gaK+2Q9ppa0SoJlXVJqVrpKRVXx24JLRgW7YDqab99xkbCLB0
2cqbP3++7+67O8LrQ555BUiVcjbzAzz2PWAxT1K2nfkPq1v0xb+ORqGQ/Bli7Rk2UzN/p7WYEpLT
AhimgsY7wFxuyeL+jlzisYky8prPPpkeVNo+K8sSlxf2wWQ8DsjT3XxpIuQUpUxpymLoPlfpVNnb
OY+ptmmelfcqhjpFOajEgcgSsTn7kVULc55A9uisiOxtSHqYo20l34vvSRTzHMOB5iKDkDSgo1Cp
0w2NtQF0plACOQ9JB3Ss2vWoSiNAyx9fF8tv96uQFD05RnOIVvOld2Oj2OPIXZmmCDBRQUWtX+Ez
LShuQgSfQ9IDurz4RXHW3kxwcIUnFb2POynS1arVqQSmOxEbD4zNWAlpJmgjTbYlly94zbkeuDR0
yj1BFROZKZAaJHIaf3rX8+8Cf8KXA9ssQUJmBqaABdU70hZSp+2O632adWOKbL81Q3hEOmgffG/J
50p3w+kUTxde1zHIqUFUU2hdmjslIIAlZrOPDezjr4P476zsXENLWL/RTdJN5Qh/QOi4zAWTILhK
NZev2OxfG4lUy7ihykiY3w1uZjjmEpqBRgnVdJ2yxEMo+g8D3o78DxYMtf/S0GZ8P/4cbOCvU6NN
hnl3ENdiu7LVPzsa/QaRUMJF5QUAAA==
EOF

# Setup dirs and rename this file
mkdir -p src/main/java/com/example
mv Upstream.java src/main/java/com/example/TlsDemoApplication.java

# Run (starts on http://localhost:8080)
mvn clean spring-boot:run

# Test with curl
curl -D- -H "X-Client-TLS-info: eyJzdWJqZWN0IjogIkZvbyJ9Cg==" 'http://localhost:8080/'

*/

package com.example;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;

@SpringBootApplication
public class TlsDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(TlsDemoApplication.class, args);
    }
}

@RestController
class TlsController {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @GetMapping("/")
    public ResponseEntity<String> index(@RequestHeader(value = "X-Client-TLS-Info", required = false) String header) {
        if (header == null || header.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized: missing X-Client-TLS-Info header");
        }

        try {
            byte[] decoded = Base64.getDecoder().decode(header);
            JsonNode node = objectMapper.readTree(decoded);
            String subject = node.path("subject").asText(""); // Defaults to empty if missing
            if (subject.isEmpty()) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("JSON parse error: no subject field");
            }
            return ResponseEntity.ok("Client Subject: " + subject);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Decode/Parse error: " + e.getMessage());
        }
    }
}
