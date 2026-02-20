/*
 * Copyright 2026 Bundesagentur für Arbeit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.arbeitsagentur.keycloak.wallet.verification;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = VerifierTestApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ConformanceUiIntegrationTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String PLAN_ID = "plan-123";
    private static final String API_KEY = "test-conformance-key";
    private static volatile HttpServer conformanceStub;
    private static volatile String conformanceBaseUrl;

    @LocalServerPort
    int port;

    @DynamicPropertySource
    static void dynamicProperties(DynamicPropertyRegistry registry) {
        ensureConformanceStub();
        registry.add("verifier.conformance.base-url", () -> "http://unused.example.invalid");
        registry.add("wallet.public-base-url", () -> "https://example.conformance.test/wallet");
        registry.add("wallet.keycloak-base-url", () -> "http://keycloak.test");
        registry.add("wallet.realm", () -> "wallet-demo");
        registry.add("wallet.client-id", () -> "wallet-mock");
        registry.add("wallet.client-secret", () -> "secret");
        registry.add("wallet.wallet-did", () -> "did:example:test-wallet");
        registry.add("wallet.storage-dir", () -> "target/test-wallet-storage");
        registry.add("wallet.wallet-key-file", () -> "target/test-wallet-keys.json");
    }

    @AfterAll
    static void stopStub() {
        if (conformanceStub != null) {
            conformanceStub.stop(0);
        }
    }

    @Test
    void conformancePageIncludesFlowViewAssetsBeforeRun() throws Exception {
        String appBase = "http://localhost:" + port;
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                .build();

        HttpResponse<String> conformanceInitial = client.send(
                HttpRequest.newBuilder(URI.create(appBase + "/verifier/conformance")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(conformanceInitial.statusCode()).isEqualTo(200);
        assertThat(conformanceInitial.body()).contains("/css/verification-flow.css");
        assertThat(conformanceInitial.body()).contains("/js/verification-flow-view.js");
        assertThat(conformanceInitial.body()).doesNotContain("id=\"conformanceFlowGraph\"");

        HttpResponse<String> flowCss = client.send(
                HttpRequest.newBuilder(URI.create(appBase + "/css/verification-flow.css"))
                        .header("Accept", "text/css")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(flowCss.statusCode()).isEqualTo(200);
        assertThat(flowCss.body()).contains(".flow-graph");

        HttpResponse<String> flowJs = client.send(
                HttpRequest.newBuilder(URI.create(appBase + "/js/verification-flow-view.js"))
                        .header("Accept", "text/javascript")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(flowJs.statusCode()).isEqualTo(200);
        assertThat(flowJs.body()).contains("VerificationFlowView");
    }

    @Test
    void loadsConformancePlanAndRunsModuleThroughConformanceUi() throws Exception {
        String appBase = "http://localhost:" + port;
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                .build();

        HttpResponse<String> verifierInitial = client.send(
                HttpRequest.newBuilder(URI.create(appBase + "/verifier")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(verifierInitial.statusCode()).isEqualTo(200);
        assertThat(verifierInitial.body()).contains("/verifier/conformance");

        HttpResponse<String> conformanceInitial = client.send(
                HttpRequest.newBuilder(URI.create(appBase + "/verifier/conformance")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(conformanceInitial.statusCode()).isEqualTo(200);
        assertThat(conformanceInitial.body()).contains("OIDF Conformance Suite");
        assertThat(conformanceInitial.body()).contains("/css/verification-flow.css");
        assertThat(conformanceInitial.body()).contains("/js/verification-flow-view.js");

        String form = "planId=" + URLEncoder.encode(PLAN_ID, StandardCharsets.UTF_8)
                + "&baseUrl=" + URLEncoder.encode(conformanceBaseUrl + "/api", StandardCharsets.UTF_8)
                + "&apiKey=" + URLEncoder.encode(API_KEY, StandardCharsets.UTF_8);
        HttpResponse<String> loadResponse = client.send(
                HttpRequest.newBuilder(URI.create(appBase + "/verifier/conformance/load"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(loadResponse.statusCode()).isEqualTo(302);
        String location = loadResponse.headers().firstValue("Location").orElse(null);
        assertThat(location).isNotBlank();
        String redirectTarget = location.startsWith("http") ? location : appBase + location;

        HttpResponse<String> afterLoadConformance = client.send(
                HttpRequest.newBuilder(URI.create(redirectTarget)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(afterLoadConformance.statusCode()).isEqualTo(200);
        String conformanceHtml = afterLoadConformance.body();

        assertThat(conformanceHtml).contains("value=\"" + conformanceBaseUrl + "\"");
        assertThat(conformanceHtml).contains("API key stored in session.");
        assertThat(conformanceHtml).doesNotContain(API_KEY);

        assertThat(conformanceHtml).contains("Plan: oid4vp-id3-verifier-test-plan");
        assertThat(conformanceHtml).contains("http://stub-wallet/auth");

        assertThat(conformanceHtml).contains("oid4vp-id3-verifier-request-uri-signed");
        assertThat(conformanceHtml).contains("instance-1");
        assertThat(conformanceHtml).contains("PASSED");

        String runForm = "planId=" + URLEncoder.encode(PLAN_ID, StandardCharsets.UTF_8)
                + "&module=" + URLEncoder.encode("oid4vp-id3-verifier-request-uri-signed", StandardCharsets.UTF_8);
        HttpResponse<String> runResponse = client.send(
                HttpRequest.newBuilder(URI.create(appBase + "/verifier/conformance/run"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(runForm))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(runResponse.statusCode()).isEqualTo(302);
        String runLocation = runResponse.headers().firstValue("Location").orElse(null);
        assertThat(runLocation).isNotBlank();
        String runTarget = runLocation.startsWith("http") ? runLocation : appBase + runLocation;
        HttpResponse<String> afterRun = client.send(
                HttpRequest.newBuilder(URI.create(runTarget)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(afterRun.statusCode()).isEqualTo(200);
        assertThat(afterRun.body()).contains("data-run-id=\"instance-2\"");
        assertThat(afterRun.body()).contains("log-detail.html?log=instance-2");
        assertThat(afterRun.body()).contains("instance-2");
        assertThat(afterRun.body()).contains("id=\"conformanceFlowGraph\"");
        assertThat(afterRun.body()).contains("id=\"conformanceFlowDetails\"");
        assertThat(afterRun.body()).contains("data-flow-api-base=\"/verifier/api/flow\"");

        HttpResponse<String> refresh = client.send(
                HttpRequest.newBuilder(URI.create(appBase + "/verifier/conformance/refresh"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(""))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(refresh.statusCode()).isEqualTo(302);
        String refreshLocation = refresh.headers().firstValue("Location").orElse(null);
        assertThat(refreshLocation).isNotBlank();
        String refreshTarget = refreshLocation.startsWith("http") ? refreshLocation : appBase + refreshLocation;
        HttpResponse<String> afterRefresh = client.send(
                HttpRequest.newBuilder(URI.create(refreshTarget)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(afterRefresh.statusCode()).isEqualTo(200);
        assertThat(afterRefresh.body()).doesNotContain("HTTP 401");

        String startBody = "walletAuthEndpoint=" + URLEncoder.encode("https://wallet.example/authorize", StandardCharsets.UTF_8);
        HttpResponse<String> verifierStart = client.send(
                HttpRequest.newBuilder(URI.create(appBase + "/verifier/start"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(startBody))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(verifierStart.statusCode()).isEqualTo(302);
        String verifierStartLocation = verifierStart.headers().firstValue("Location").orElse(null);
        assertThat(verifierStartLocation).isNotBlank();
        String state = queryParam(URI.create(verifierStartLocation), "state");
        assertThat(state).isNotBlank();

        HttpResponse<String> flow = client.send(
                HttpRequest.newBuilder(URI.create(appBase + "/verifier/api/flow/" + URLEncoder.encode(state, StandardCharsets.UTF_8)))
                        .header("Accept", "application/json")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(flow.statusCode()).isEqualTo(200);
        List<Map<String, Object>> flowEntries = OBJECT_MAPPER.readValue(flow.body(), List.class);
        assertThat(flowEntries).isNotEmpty();
        assertThat(flowEntries.stream().map(entry -> String.valueOf(entry.get("title"))))
                .contains("Authorization request to wallet");
    }

    private static String queryParam(URI uri, String name) {
        if (uri == null || name == null || name.isBlank()) {
            return "";
        }
        String query = uri.getRawQuery();
        if (query == null || query.isBlank()) {
            return "";
        }
        for (String part : query.split("&")) {
            String[] kv = part.split("=", 2);
            if (kv.length == 2 && name.equals(kv[0])) {
                return URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
            }
        }
        return "";
    }

    @Test
    void verifierResultPageRendersFlowViewWhenStatePresent() throws Exception {
        String appBase = "http://localhost:" + port;
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                .build();

        String startBody = "walletAuthEndpoint=" + URLEncoder.encode("https://wallet.example/authorize", StandardCharsets.UTF_8);
        HttpResponse<String> verifierStart = client.send(
                HttpRequest.newBuilder(URI.create(appBase + "/verifier/start"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(startBody))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(verifierStart.statusCode()).isEqualTo(302);
        String verifierStartLocation = verifierStart.headers().firstValue("Location").orElse(null);
        assertThat(verifierStartLocation).isNotBlank();
        String state = queryParam(URI.create(verifierStartLocation), "state");
        assertThat(state).isNotBlank();

        HttpResponse<String> callback = client.send(
                HttpRequest.newBuilder(URI.create(appBase + "/verifier/callback"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString("state=" + URLEncoder.encode(state, StandardCharsets.UTF_8)))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(callback.statusCode()).isEqualTo(200);
        Map<String, Object> callbackJson = OBJECT_MAPPER.readValue(callback.body(), Map.class);
        assertThat(callbackJson).containsKey("redirect_uri");
        String redirectUri = (String) callbackJson.get("redirect_uri");
        assertThat(redirectUri).contains("/verifier/result/" + state);

        // The redirect_uri uses the public base URL (with /wallet prefix);
        // extract just the /verifier/result/... path for the local test server.
        HttpResponse<String> resultPage = client.send(
                HttpRequest.newBuilder(URI.create(appBase + "/verifier/result/" + state))
                        .header("Accept", "text/html")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(resultPage.statusCode()).isEqualTo(400);
        assertThat(resultPage.body()).contains("/css/verification-flow.css");
        assertThat(resultPage.body()).contains("/js/verification-flow-view.js");
        assertThat(resultPage.body()).contains("id=\"verificationFlowGraph\"");
        assertThat(resultPage.body()).contains("data-flow-api-base=\"/verifier/api/flow\"");
        assertThat(resultPage.body()).contains("data-flow-state=\"" + state + "\"");

        HttpResponse<String> flow = client.send(
                HttpRequest.newBuilder(URI.create(appBase + "/verifier/api/flow/" + URLEncoder.encode(state, StandardCharsets.UTF_8)))
                        .header("Accept", "application/json")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(flow.statusCode()).isEqualTo(200);
        List<Map<String, Object>> flowEntries = OBJECT_MAPPER.readValue(flow.body(), List.class);
        assertThat(flowEntries).isNotEmpty();
        assertThat(flowEntries.stream().map(entry -> String.valueOf(entry.get("title"))))
                .contains("Authorization request to wallet", "direct_post callback (missing vp_token)");
    }

    @Test
    void verifierCallbackReturnsEmptyJsonWhenStateMissing() throws Exception {
        String appBase = "http://localhost:" + port;
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                .build();

        // OID4VP 1.0 Section 8.2: response_uri MUST respond with HTTP 200
        HttpResponse<String> callback = client.send(
                HttpRequest.newBuilder(URI.create(appBase + "/verifier/callback"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(""))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(callback.statusCode()).isEqualTo(200);
        Map<String, Object> json = OBJECT_MAPPER.readValue(callback.body(), Map.class);
        assertThat(json).doesNotContainKey("redirect_uri");
    }

    private static void ensureConformanceStub() {
        if (conformanceStub != null) {
            return;
        }
        synchronized (ConformanceUiIntegrationTest.class) {
            if (conformanceStub != null) {
                return;
            }
            try {
                HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
                ConformanceStubHandler handler = new ConformanceStubHandler();
                server.createContext("/api/plan", handler);
                server.createContext("/api/info", handler);
                server.createContext("/api/runner", handler);
                server.start();
                conformanceStub = server;
                conformanceBaseUrl = "http://localhost:" + server.getAddress().getPort();
            } catch (IOException e) {
                throw new IllegalStateException("Failed to start conformance stub", e);
            }
        }
    }

    private static class ConformanceStubHandler implements HttpHandler {
        private static final String MODULE = "oid4vp-id3-verifier-request-uri-signed";
        private final List<String> instanceIds = new ArrayList<>(List.of("instance-1"));
        private int runCounter = 1;

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            if (auth == null || !auth.equals("Bearer " + API_KEY)) {
                writeJson(exchange, 401, Map.of("error", "unauthorized"));
                return;
            }

            if ("GET".equalsIgnoreCase(exchange.getRequestMethod()) && path.startsWith("/api/plan/")) {
                String id = path.substring("/api/plan/".length());
                if (!PLAN_ID.equals(id)) {
                    writeJson(exchange, 404, Map.of("error", "not_found"));
                    return;
                }

                Map<String, Object> module = new LinkedHashMap<>();
                module.put("testModule", MODULE);
                module.put("testSummary", "stub verifier module");
                module.put("variant", Map.of(
                        "response_mode", "direct_post.jwt",
                        "credential_format", "sd_jwt_vc",
                        "query_language", "dcql_query",
                        "client_id_scheme", "x509_san_dns"
                ));
                module.put("instances", List.copyOf(instanceIds));

                Map<String, Object> plan = new LinkedHashMap<>();
                plan.put("_id", PLAN_ID);
                plan.put("planName", "oid4vp-id3-verifier-test-plan");
                plan.put("description", "local stub plan");
                plan.put("exported_values", Map.of("authorization_endpoint", "http://stub-wallet/auth"));
                plan.put("modules", List.of(module));

                writeJson(exchange, 200, plan);
                return;
            }

            if ("GET".equalsIgnoreCase(exchange.getRequestMethod()) && path.startsWith("/api/info/")) {
                String testId = path.substring("/api/info/".length());
                if (!instanceIds.contains(testId)) {
                    writeJson(exchange, 404, Map.of("error", "not_found"));
                    return;
                }
                Map<String, Object> info = Map.of(
                        "_id", testId,
                        "testId", testId,
                        "testName", MODULE,
                        "planId", PLAN_ID,
                        "status", "FINISHED",
                        "result", "PASSED",
                        "started", "2025-01-01T00:00:00Z",
                        "version", "test-stub"
                );
                writeJson(exchange, 200, info);
                return;
            }

            if ("POST".equalsIgnoreCase(exchange.getRequestMethod()) && "/api/runner".equals(path)) {
                byte[] body = exchange.getRequestBody().readAllBytes();
                if (body.length > 0) {
                    writeJson(exchange, 400, Map.of("error", "request_body_not_allowed"));
                    return;
                }
                String query = exchange.getRequestURI().getQuery();
                Map<String, String> params = parseQuery(query);
                if (!PLAN_ID.equals(params.get("plan")) || !MODULE.equals(params.get("test"))) {
                    writeJson(exchange, 400, Map.of("error", "bad_request"));
                    return;
                }
                String newId = nextInstanceId();
                writeJson(exchange, 201, Map.of("id", newId));
                return;
            }

            writeJson(exchange, 404, Map.of("error", "not_found"));
        }

        private synchronized String nextInstanceId() {
            runCounter++;
            String id = "instance-" + runCounter;
            instanceIds.add(0, id);
            return id;
        }

        private Map<String, String> parseQuery(String query) {
            Map<String, String> out = new LinkedHashMap<>();
            if (query == null || query.isBlank()) {
                return out;
            }
            for (String part : query.split("&")) {
                int idx = part.indexOf('=');
                if (idx <= 0) {
                    continue;
                }
                out.put(part.substring(0, idx), part.substring(idx + 1));
            }
            return out;
        }

        private void writeJson(HttpExchange exchange, int status, Map<String, Object> payload) throws IOException {
            exchange.getResponseHeaders().add("Cache-Control", "no-store");
            byte[] bytes = OBJECT_MAPPER.writeValueAsBytes(payload);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }
}
