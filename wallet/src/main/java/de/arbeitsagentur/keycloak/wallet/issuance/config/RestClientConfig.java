package de.arbeitsagentur.keycloak.wallet.issuance.config;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.SSLContexts;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.time.Duration;

@Configuration
public class RestClientConfig {
    private final WalletProperties properties;

    public RestClientConfig(WalletProperties properties) {
        this.properties = properties;
    }

    @Bean
    RestTemplate restTemplate() {
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(5));
        factory.setConnectionRequestTimeout(Duration.ofSeconds(5));
        factory.setHttpClient(buildHttpClient());
        return new RestTemplate(factory);
    }

    private HttpClient buildHttpClient() {
        try {
            if (properties.tlsKeyStore() != null && Files.exists(properties.tlsKeyStore())) {
                String type = properties.tlsKeyStoreType() != null ? properties.tlsKeyStoreType() : "PKCS12";
                KeyStore keyStore = KeyStore.getInstance(type);
                char[] password = properties.tlsKeyStorePassword() != null
                        ? properties.tlsKeyStorePassword().toCharArray()
                        : new char[0];
                try (InputStream is = Files.newInputStream(properties.tlsKeyStore())) {
                    keyStore.load(is, password);
                }
                SSLContextBuilder builder = SSLContexts.custom().loadKeyMaterial(keyStore, password);
                SSLContext sslContext = builder.build();
                SSLConnectionSocketFactory socketFactory = SSLConnectionSocketFactoryBuilder.create()
                        .setSslContext(sslContext)
                        .build();
                PoolingHttpClientConnectionManager manager = PoolingHttpClientConnectionManagerBuilder.create()
                        .setSSLSocketFactory(socketFactory)
                        .build();
                return HttpClients.custom().setConnectionManager(manager).build();
            }
        } catch (Exception e) {
            throw new IllegalStateException("Unable to configure TLS client", e);
        }
        return HttpClients.createDefault();
    }
}
