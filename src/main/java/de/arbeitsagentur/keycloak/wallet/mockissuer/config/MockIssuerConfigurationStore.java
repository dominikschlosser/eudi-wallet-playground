package de.arbeitsagentur.keycloak.wallet.mockissuer.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

@Component
public class MockIssuerConfigurationStore {
    private static final Logger LOG = LoggerFactory.getLogger(MockIssuerConfigurationStore.class);

    private final ObjectMapper objectMapper;
    private final Path configurationFile;
    private final List<MockIssuerProperties.CredentialConfiguration> configurations = new ArrayList<>();
    private final ReadWriteLock lock = new ReentrantReadWriteLock();

    public MockIssuerConfigurationStore(MockIssuerProperties properties, ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.configurationFile = properties.configurationFile();
        List<MockIssuerProperties.CredentialConfiguration> loaded = loadFromFile()
                .orElseGet(properties::configurations);
        if (loaded != null) {
            configurations.addAll(loaded);
        }
    }

    public List<MockIssuerProperties.CredentialConfiguration> configurations() {
        lock.readLock().lock();
        try {
            return List.copyOf(configurations);
        } finally {
            lock.readLock().unlock();
        }
    }

    public Optional<MockIssuerProperties.CredentialConfiguration> findById(String id) {
        if (!StringUtils.hasText(id)) {
            return Optional.empty();
        }
        lock.readLock().lock();
        try {
            return configurations.stream()
                    .filter(cfg -> cfg.id().equals(id))
                    .findFirst();
        } finally {
            lock.readLock().unlock();
        }
    }

    public Optional<MockIssuerProperties.CredentialConfiguration> defaultConfiguration() {
        lock.readLock().lock();
        try {
            return configurations.isEmpty() ? Optional.empty() : Optional.of(configurations.get(0));
        } finally {
            lock.readLock().unlock();
        }
    }

    public MockIssuerProperties.CredentialConfiguration addConfiguration(MockIssuerProperties.CredentialConfiguration raw) {
        MockIssuerProperties.CredentialConfiguration normalized = normalize(raw);
        validate(normalized);
        lock.writeLock().lock();
        try {
            boolean exists = configurations.stream()
                    .anyMatch(cfg -> cfg.id().equalsIgnoreCase(normalized.id()));
            if (exists) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Credential configuration id already exists");
            }
            configurations.add(normalized);
            persist();
            return normalized;
        } finally {
            lock.writeLock().unlock();
        }
    }

    private Optional<List<MockIssuerProperties.CredentialConfiguration>> loadFromFile() {
        if (configurationFile == null || !Files.exists(configurationFile)) {
            return Optional.empty();
        }
        try {
            JsonNode node = objectMapper.readTree(configurationFile.toFile());
            JsonNode configsNode = node.isObject() ? node.get("configurations") : node;
            if (configsNode == null || !configsNode.isArray()) {
                LOG.warn("Ignoring mock issuer configuration file {} because it does not contain an array", configurationFile);
                return Optional.empty();
            }
            List<MockIssuerProperties.CredentialConfiguration> parsed = objectMapper.readerFor(
                    new TypeReference<List<MockIssuerProperties.CredentialConfiguration>>() {
                    }).readValue(configsNode);
            if (parsed.isEmpty()) {
                LOG.warn("Mock issuer configuration file {} is present but empty", configurationFile);
                return Optional.empty();
            }
            return Optional.of(parsed);
        } catch (IOException e) {
            LOG.warn("Failed to read mock issuer configurations from {}", configurationFile, e);
            return Optional.empty();
        }
    }

    private MockIssuerProperties.CredentialConfiguration normalize(MockIssuerProperties.CredentialConfiguration cfg) {
        if (cfg == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No credential configuration provided");
        }
        String id = trimToNull(cfg.id());
        String format = trimToNull(cfg.format());
        String scope = trimToNull(cfg.scope());
        String name = trimToNull(cfg.name());
        String vct = trimToNull(cfg.vct());
        List<MockIssuerProperties.ClaimTemplate> claims = cfg.claims() == null ? List.of() : cfg.claims().stream()
                .filter(Objects::nonNull)
                .map(claim -> new MockIssuerProperties.ClaimTemplate(
                        trimToNull(claim.name()),
                        trimToNull(claim.label()),
                        trimToNull(claim.defaultValue()),
                        claim.required()))
                .filter(claim -> StringUtils.hasText(claim.name()))
                .collect(Collectors.toCollection(ArrayList::new));
        return new MockIssuerProperties.CredentialConfiguration(
                id,
                StringUtils.hasText(format) ? format : "dc+sd-jwt",
                scope,
                name,
                vct,
                claims
        );
    }

    private void validate(MockIssuerProperties.CredentialConfiguration cfg) {
        if (!StringUtils.hasText(cfg.id())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "id is required");
        }
        if (!StringUtils.hasText(cfg.name())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "name is required");
        }
        if (!StringUtils.hasText(cfg.scope())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "scope is required");
        }
        if (!StringUtils.hasText(cfg.vct())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "vct is required");
        }
        if (!"dc+sd-jwt".equalsIgnoreCase(cfg.format())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Only dc+sd-jwt credentials are supported");
        }
    }

    private void persist() {
        try {
            Path parent = configurationFile.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            List<MockIssuerProperties.CredentialConfiguration> snapshot = List.copyOf(configurations);
            objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValue(configurationFile.toFile(), Map.of("configurations", snapshot));
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to persist mock issuer configurations", e);
        }
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
