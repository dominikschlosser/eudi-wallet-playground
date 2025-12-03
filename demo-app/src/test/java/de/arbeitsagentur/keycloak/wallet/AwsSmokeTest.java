package de.arbeitsagentur.keycloak.wallet;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.cookie.Cookie;
import org.apache.hc.client5.http.cookie.StandardCookieSpec;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.client5.http.ssl.HttpsSupport;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.SSLInitializationException;
import org.apache.hc.core5.ssl.TrustStrategy;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.net.ssl.SSLContext;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfSystemProperty(named = "aws.smoke", matches = "(?i)true")
class AwsSmokeTest {

    private static final Logger LOG = LoggerFactory.getLogger(AwsSmokeTest.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final RequestConfig REQUEST_CONFIG = RequestConfig.custom()
            .setRedirectsEnabled(false)
            .setCookieSpec(StandardCookieSpec.RELAXED)
            .build();
    private String expectedHost;
    private String expectedScheme = "https";

    @Test
    void issuanceAndVerificationOnAws() throws Exception {
        URI base = walletBase();
        String username = firstNonBlank(
                System.getProperty("aws.wallet.username"),
                System.getenv("AWS_WALLET_USERNAME"),
                System.getenv("AWS_WALLET_USER"),
                "test"
        );
        String password = firstNonBlank(
                System.getProperty("aws.wallet.password"),
                System.getenv("AWS_WALLET_PASSWORD"),
                System.getenv("AWS_WALLET_PASS"),
                "test"
        );

        BasicCookieStore cookieStore = new BasicCookieStore();
        HttpClientContext context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
        try (CloseableHttpClient client = buildHttpClient(cookieStore)) {
            LOG.info("Running AWS smoke test against {}", base);
            HtmlPage walletHome = fetchHtmlFollowingRedirects(client, context, base);
            authenticate(base, walletHome, client, context, username, password);
            HtmlPage homeAfterLogin = fetchHtmlFollowingRedirects(client, context, base);
            verifyNavigationLinks(homeAfterLogin, client, context, base);

            JsonNode session = readSession(base, client, context);
            assertThat(session.path("authenticated").asBoolean())
                    .as("User should be logged in at %s", base)
                    .isTrue();

            JsonNode credential = issueCredential(base, client, context);
            assertThat(credential.path("credentialSubject").path("given_name").asText()).isNotBlank();
            assertThat(credential.path("rawCredential").asText()).isNotBlank();

            String dcql = fetchDefaultDcqlQuery(base, client, context);
            URI walletAuth = startPresentationRequest(base, client, context, dcql);
            PresentationForm form = continuePresentationFlow(base, client, context, walletAuth);

            HttpPost callbackPost = new HttpPost(form.action());
            callbackPost.setConfig(REQUEST_CONFIG);
            callbackPost.setEntity(new UrlEncodedFormEntity(toParams(form.fields()), StandardCharsets.UTF_8));
            try (ResponseWithUri verifierResult = executeFollowRedirects(client, context, callbackPost)) {
                String body = new String(verifierResult.response().getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
                assertThat(verifierResult.response().getCode())
                        .withFailMessage("Verifier callback failed. Body:%n%s", body)
                        .isEqualTo(200);
                assertThat(body).contains("Verified credential");
            }
        }
    }

    private URI walletBase() {
        String raw = firstNonBlank(
                System.getProperty("aws.wallet.base-url"),
                System.getenv("AWS_WALLET_BASE_URL")
        );
        if (raw == null || raw.isBlank()) {
            throw new IllegalStateException("Set AWS_WALLET_BASE_URL or -Daws.wallet.base-url to the deployed wallet base (e.g. https://wallet.example.com/wallet)");
        }
        String normalized = raw.trim();
        if (!normalized.endsWith("/")) {
            normalized = normalized + "/";
        }
        URI uri = URI.create(normalized);
        expectedHost = uri.getHost();
        expectedScheme = uri.getScheme() != null ? uri.getScheme() : "https";
        return uri;
    }

    private CloseableHttpClient buildHttpClient(BasicCookieStore cookieStore) {
        SSLContext sslContext;
        SSLContextBuilder builder = SSLContextBuilder.create();
        String trustStore = firstNonBlank(
                System.getProperty("aws.wallet.trust-store"),
                System.getenv("AWS_WALLET_TRUSTSTORE")
        );
        String trustStorePassword = firstNonBlank(
                System.getProperty("aws.wallet.trust-store-password"),
                System.getenv("AWS_WALLET_TRUSTSTORE_PASSWORD")
        );
        String trustStoreType = firstNonBlank(
                System.getProperty("aws.wallet.trust-store-type"),
                System.getenv("AWS_WALLET_TRUSTSTORE_TYPE"),
                KeyStore.getDefaultType()
        );
        if (trustStore != null && !trustStore.isBlank()) {
            try {
                KeyStore ks = KeyStore.getInstance(trustStoreType);
                try (InputStream in = Files.newInputStream(Path.of(trustStore))) {
                    ks.load(in, trustStorePassword != null ? trustStorePassword.toCharArray() : null);
                }
                builder.loadTrustMaterial(ks, (TrustStrategy) null);
                sslContext = builder.build();
                LOG.info("AWS smoke test using trust store {} (type {})", trustStore, trustStoreType);
            } catch (Exception e) {
                throw new SSLInitializationException("Failed to load trust store " + trustStore, e);
            }
        } else {
            try {
                builder.loadTrustMaterial((TrustStrategy) null);
                sslContext = builder.build();
            } catch (Exception e) {
                throw new SSLInitializationException("Failed to initialize default SSL context", e);
            }
        }
        SSLConnectionSocketFactory sslFactory = new SSLConnectionSocketFactory(sslContext, HttpsSupport.getDefaultHostnameVerifier());
        var cm = PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(sslFactory)
                .build();
        return HttpClients.custom()
                .setConnectionManager(cm)
                .setDefaultCookieStore(cookieStore)
                .setDefaultRequestConfig(REQUEST_CONFIG)
                .build();
    }

    private void authenticate(URI base, HtmlPage walletHome, CloseableHttpClient client, HttpClientContext context,
                              String username, String password) throws Exception {
        for (int attempt = 0; attempt < 2; attempt++) {
            URI loginLink = findLink(walletHome.document(), "auth/login");
            if (loginLink == null) {
                loginLink = base.resolve("auth/login");
            } else {
                loginLink = resolveRedirect(base, loginLink.toString());
            }
            HttpGet startLogin = new HttpGet(loginLink);
            startLogin.setConfig(REQUEST_CONFIG);
            try (CloseableHttpResponse loginRedirect = client.execute(startLogin, context)) {
                assertThat(loginRedirect.getCode()).isEqualTo(302);
                URI authorize = resolveRedirect(base, loginRedirect.getFirstHeader("Location").getValue());
                HtmlPage loginPage = fetchHtmlFollowingRedirects(client, context, authorize);
                LoginForm loginForm = extractLoginForm(loginPage.document(), loginPage.uri());
                loginForm.fields().put("username", username);
                loginForm.fields().put("password", password);

                HttpPost loginPost = new HttpPost(loginForm.action());
                loginPost.setConfig(REQUEST_CONFIG);
                loginPost.setEntity(new UrlEncodedFormEntity(toParams(loginForm.fields()), StandardCharsets.UTF_8));
                String cookieHeader = buildCookieHeaderFor(loginForm.action(), context.getCookieStore().getCookies());
                if (!cookieHeader.isBlank()) {
                    loginPost.setHeader("Cookie", cookieHeader);
                }
                try (ResponseWithUri loginResult = executeFollowRedirects(client, context, loginPost)) {
                    String body = loginResult.response().getEntity() != null
                            ? new String(loginResult.response().getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8)
                            : "";
                    if (loginResult.response().getCode() == 400
                            && body.contains("Restart login cookie not found")
                            && attempt == 0) {
                        context.getCookieStore().clear();
                        continue;
                    }
                    assertThat(loginResult.response().getCode())
                            .withFailMessage("Login flow failed. HTTP %s at %s Body:%n%s",
                                    loginResult.response().getCode(), loginResult.uri(), body)
                            .isEqualTo(200);
                    return;
                }
            }
        }
        throw new IllegalStateException("Login flow did not complete");
    }

    private JsonNode readSession(URI base, CloseableHttpClient client, HttpClientContext context) throws IOException {
        HttpGet getSession = new HttpGet(base.resolve("api/session"));
        getSession.setConfig(REQUEST_CONFIG);
        try (CloseableHttpResponse response = client.execute(getSession, context)) {
            assertThat(response.getCode()).isEqualTo(200);
            return OBJECT_MAPPER.readTree(response.getEntity().getContent());
        }
    }

    private JsonNode issueCredential(URI base, CloseableHttpClient client, HttpClientContext context) throws IOException {
        HttpPost issue = new HttpPost(base.resolve("api/issue"));
        issue.setConfig(REQUEST_CONFIG);
        try (CloseableHttpResponse issueResponse = client.execute(issue, context)) {
            String body = issueResponse.getEntity() != null
                    ? new String(issueResponse.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8)
                    : "";
            assertThat(issueResponse.getCode())
                    .withFailMessage("Issuance failed. HTTP %s Body:%n%s", issueResponse.getCode(), body)
                    .isEqualTo(200);
            return OBJECT_MAPPER.readTree(body);
        }
    }

    private String fetchDefaultDcqlQuery(URI base, CloseableHttpClient client, HttpClientContext context) throws IOException {
        HttpGet get = new HttpGet(base.resolve("verifier/default"));
        get.setConfig(REQUEST_CONFIG);
        try (CloseableHttpResponse resp = client.execute(get, context)) {
            assertThat(resp.getCode()).isEqualTo(200);
            JsonNode json = OBJECT_MAPPER.readTree(resp.getEntity().getContent());
            return json.path("dcql_query").asText();
        }
    }

    private URI startPresentationRequest(URI base, CloseableHttpClient client, HttpClientContext context, String dcqlQuery)
            throws IOException {
        HttpPost verifierStart = new HttpPost(base.resolve("verifier/start"));
        verifierStart.setConfig(REQUEST_CONFIG);
        verifierStart.setEntity(new UrlEncodedFormEntity(List.of(new BasicNameValuePair("dcqlQuery", dcqlQuery)),
                StandardCharsets.UTF_8));
        try (CloseableHttpResponse startResponse = client.execute(verifierStart, context)) {
            assertThat(startResponse.getCode()).isEqualTo(302);
            return resolveRedirect(base, startResponse.getFirstHeader("Location").getValue());
        }
    }

    private PresentationForm continuePresentationFlow(URI base, CloseableHttpClient client, HttpClientContext context,
                                                      URI walletAuth) throws IOException {
        HtmlPage document = fetchHtmlFollowingRedirects(client, context, walletAuth);
        assertThat(document.document().selectFirst("form[action$=\"/oid4vp/consent\"]"))
                .withFailMessage("Consent form missing. Body: %s", document.document().text())
                .isNotNull();

        List<NameValuePair> consentParams = new ArrayList<>();
        consentParams.add(new BasicNameValuePair("decision", "accept"));
        Map<String, List<Element>> radioGroups = document.document().select("input[type=radio][name^=selection-]")
                .stream()
                .collect(Collectors.groupingBy(input -> input.attr("name"), Collectors.toList()));
        radioGroups.forEach((name, inputs) -> {
            if (!inputs.isEmpty()) {
                consentParams.add(new BasicNameValuePair(name, inputs.get(0).attr("value")));
            }
        });
        HttpPost consentPost = new HttpPost(base.resolve("oid4vp/consent"));
        consentPost.setConfig(REQUEST_CONFIG);
        consentPost.setEntity(new UrlEncodedFormEntity(consentParams, StandardCharsets.UTF_8));
        try (CloseableHttpResponse consentResponse = client.execute(consentPost, context)) {
            assertThat(consentResponse.getCode()).isEqualTo(200);
            String body = new String(consentResponse.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
            Document submitDoc = Jsoup.parse(body);
            Element presentationForm = submitDoc.selectFirst("form");
            assertThat(presentationForm).withFailMessage("Presentation form missing after consent. Body: %s", body)
                    .isNotNull();
            Map<String, String> fields = new LinkedHashMap<>();
            for (Element input : presentationForm.select("input")) {
                String name = input.attr("name");
                if (name != null && !name.isBlank()) {
                    fields.put(name, input.attr("value"));
                }
            }
            URI action = resolveRedirect(base, presentationForm.attr("action"));
            return new PresentationForm(action, fields);
        }
    }

    private HtmlPage fetchHtmlFollowingRedirects(CloseableHttpClient client, HttpClientContext context, URI uri)
            throws IOException {
        HttpGet request = new HttpGet(uri);
        request.setConfig(REQUEST_CONFIG);
        try (ResponseWithUri response = executeFollowRedirects(client, context, request)) {
            String body = response.response().getEntity() != null
                    ? new String(response.response().getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8)
                    : "";
            assertThat(response.response().getCode())
                    .withFailMessage("GET %s returned %s. Body:%n%s",
                            response.uri(), response.response().getCode(), body)
                    .isEqualTo(200);
            return new HtmlPage(
                    response.uri(),
                    Jsoup.parse(body, response.uri().toString())
            );
        }
    }

    private LoginForm extractLoginForm(Document loginPage, URI pageUri) {
        Element targetForm = null;
        for (Element form : loginPage.select("form")) {
            Elements inputs = form.select("input");
            boolean hasUsername = inputs.stream().anyMatch(input -> "username".equals(input.attr("name")));
            boolean hasPassword = inputs.stream().anyMatch(input -> "password".equals(input.attr("name")));
            if (hasUsername && hasPassword) {
                targetForm = form;
                break;
            }
        }
        if (targetForm == null) {
            targetForm = loginPage.selectFirst("form");
        }
        assertThat(targetForm).withFailMessage("Login form not found").isNotNull();

        Map<String, String> fields = new LinkedHashMap<>();
        for (Element input : targetForm.select("input")) {
            String name = input.attr("name");
            if (name == null || name.isBlank()) {
                continue;
            }
            fields.put(name, input.attr("value"));
        }
        URI action = resolveRedirect(pageUri, targetForm.attr("action"));
        return new LoginForm(action, fields);
    }

    private ResponseWithUri executeFollowRedirects(CloseableHttpClient client, HttpClientContext context,
                                                   HttpUriRequestBase initial) throws IOException {
        HttpUriRequestBase currentRequest = initial;
        CloseableHttpResponse response = client.execute(currentRequest, context);
        URI current = URI.create(currentRequest.getRequestUri());
        int hops = 0;
        List<String> trace = new ArrayList<>();
        while (isRedirect(response)) {
            String location = response.getFirstHeader("Location").getValue();
            URI next = resolveRedirect(current, location);
            if (expectedHost != null && next.getHost() != null && next.getHost().equalsIgnoreCase(expectedHost)) {
                if (!expectedScheme.equalsIgnoreCase(next.getScheme())) {
                    response.close();
                    throw new IllegalStateException("Redirect uses wrong scheme: " + next);
                }
            }
            if (location.contains("response_uri=http://")) {
                response.close();
                throw new IllegalStateException("Redirect contains insecure response_uri: " + location);
            }
            if (expectedHost != null && location.contains("iss=http://"+expectedHost)) {
                response.close();
                throw new IllegalStateException("Redirect contains insecure iss parameter: " + location);
            }
            trace.add("%s %s -> %s".formatted(response.getCode(), current, next));
            if (++hops > 10) {
                response.close();
                throw new IllegalStateException("Too many redirects: %s".formatted(String.join(" | ", trace)));
            }
            response.close();
            HttpUriRequestBase follow;
            int code = response.getCode();
            if (currentRequest instanceof HttpPost originalPost && (code == 307 || code == 308)) {
                HttpPost retry = new HttpPost(next);
                if (originalPost.getEntity() != null) {
                    retry.setEntity(originalPost.getEntity());
                }
                retry.setHeaders(originalPost.getHeaders());
                follow = retry;
            } else {
                follow = new HttpGet(next);
            }
            follow.setConfig(REQUEST_CONFIG);
            response = client.execute(follow, context);
            current = next;
            currentRequest = follow;
        }
        if (!trace.isEmpty()) {
            LOG.info("Redirect chain ({} steps): {}", trace.size(), String.join(" | ", trace));
        }
        return new ResponseWithUri(response, current);
    }

    private boolean isRedirect(CloseableHttpResponse response) {
        int code = response.getCode();
        return code >= 300 && code < 400;
    }

    private URI resolveRedirect(URI current, String location) {
        URI candidate = URI.create(location);
        if (candidate.isAbsolute()) {
            return candidate;
        }
        return current.resolve(location);
    }

    private List<NameValuePair> toParams(Map<String, String> fields) {
        List<NameValuePair> params = new ArrayList<>();
        fields.forEach((k, v) -> params.add(new BasicNameValuePair(k, v)));
        return params;
    }

    private URI findLink(Document doc, String contains) {
        if (doc == null) {
            return null;
        }
        for (Element link : doc.select("a[href]")) {
            String href = link.attr("href");
            if (href != null && href.contains(contains)) {
                return URI.create(href);
            }
        }
        return null;
    }

    private void verifyNavigationLinks(HtmlPage walletHome, CloseableHttpClient client, HttpClientContext context, URI base)
            throws IOException {
        URI mockIssuer = resolveOptional(base, walletHome.document(), "/mock-issuer");
        URI verifier = resolveOptional(base, walletHome.document(), "/verifier");
        if (mockIssuer != null) {
            assertThat(doGet(client, context, mockIssuer)).isEqualTo(200);
        }
        if (verifier != null) {
            assertThat(doGet(client, context, verifier)).isEqualTo(200);
        }
    }

    private URI resolveOptional(URI base, Document doc, String contains) {
        URI link = findLink(doc, contains);
        if (link == null) {
            return null;
        }
        return resolveRedirect(base, link.toString());
    }

    private int doGet(CloseableHttpClient client, HttpClientContext context, URI uri) throws IOException {
        HttpGet get = new HttpGet(uri);
        get.setConfig(REQUEST_CONFIG);
        try (CloseableHttpResponse resp = client.execute(get, context)) {
            return resp.getCode();
        }
    }

    private String buildCookieHeaderFor(URI target, List<Cookie> cookies) {
        String host = target.getHost();
        String path = target.getPath();
        return cookies.stream()
                .filter(cookie -> cookieApplies(cookie, host, path))
                .map(cookie -> cookie.getName() + "=" + cookie.getValue())
                .collect(Collectors.joining("; "));
    }

    private boolean cookieApplies(Cookie cookie, String host, String path) {
        String domain = cookie.getDomain();
        if (domain != null && !host.endsWith(domain.replaceFirst("^\\.", ""))) {
            return false;
        }
        String cookiePath = cookie.getPath();
        if (cookiePath != null && !path.startsWith(cookiePath)) {
            return false;
        }
        return true;
    }

    private String firstNonBlank(String... candidates) {
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank()) {
                return candidate;
            }
        }
        return null;
    }

    private record PresentationForm(URI action, Map<String, String> fields) {
    }

    private record LoginForm(URI action, Map<String, String> fields) {
    }

    private record HtmlPage(URI uri, Document document) {
    }

    private record ResponseWithUri(CloseableHttpResponse response, URI uri) implements AutoCloseable {
        @Override
        public void close() throws IOException {
            response.close();
        }
    }
}
