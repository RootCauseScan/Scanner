package com.example.demo;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
public class WebsiteTestService {

    private final RestTemplate rest = new RestTemplate();
    private static final String INTERNAL_URL = "https://status.internal.example.com/health";

    // No user data reaches the outbound call: the host is hardcoded.
    @PostMapping("/website/health")
    public String healthCheck(@RequestBody WebsiteTestRequest request) {
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<String> entity = new HttpEntity<>(headers);
        // ok: java-ssrf-resttemplate
        return this.rest.exchange(INTERNAL_URL, HttpMethod.GET, entity, String.class).getBody();
    }
}

class WebsiteTestRequest {
    public String url;
}
