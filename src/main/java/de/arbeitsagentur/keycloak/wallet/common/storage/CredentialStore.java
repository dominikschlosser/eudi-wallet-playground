package de.arbeitsagentur.keycloak.wallet.common.storage;

import de.arbeitsagentur.keycloak.wallet.issuance.config.WalletProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

@Component
public class CredentialStore {
    private final WalletProperties properties;
    private final ObjectMapper objectMapper;

    public CredentialStore(WalletProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    public synchronized Path saveCredential(String userId, Object credential) {
        try {
            Files.createDirectories(properties.storageDir());
            String safeUser = userId == null ? "anon" : userId.replaceAll("[^a-zA-Z0-9_-]", "_");
            Path file = properties.storageDir()
                    .resolve("%s-%d-%s.json".formatted(safeUser, System.currentTimeMillis(), UUID.randomUUID()));
            objectMapper.writeValue(file.toFile(), credential);
            return file;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to store credential", e);
        }
    }

    public synchronized List<Object> listCredentials(String userId) {
        try {
            List<Object> items = new ArrayList<>();
            for (Path path : listFiles()) {
                if (belongsToUser(path, userId)) {
                    try {
                        items.add(objectMapper.readValue(path.toFile(), Object.class));
                    } catch (IOException ignored) {
                    }
                }
            }
            return items;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read credential store", e);
        }
    }

    public synchronized List<Entry> listCredentialEntries(String userId) {
        try {
            List<Entry> items = new ArrayList<>();
            for (Path path : listFiles()) {
                if (!belongsToUser(path, userId)) {
                    continue;
                }
                try {
                    String fileName = path.getFileName().toString();
                    Object data = objectMapper.readValue(path.toFile(), Object.class);
                    items.add(new Entry(fileName, data));
                } catch (IOException ignored) {
                }
            }
            return items;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read credential store", e);
        }
    }

    public synchronized boolean deleteCredential(String userId, String fileName) {
        if (fileName == null || fileName.isBlank()) {
            return false;
        }
        Path target = properties.storageDir().resolve(fileName);
        if (!Files.exists(target)) {
            return false;
        }
        if (userId != null && !fileName.startsWith(userId)) {
            return false;
        }
        try {
            Files.deleteIfExists(target);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public record Entry(String fileName, Object credential) {
    }

    private List<Path> listFiles() throws IOException {
        if (!Files.exists(properties.storageDir())) {
            return List.of();
        }
        try (var stream = Files.list(properties.storageDir())) {
            return stream
                    .filter(Files::isRegularFile)
                    .sorted(Comparator.naturalOrder())
                    .toList();
        }
    }

    private boolean belongsToUser(Path path, String userId) {
        if (userId == null || userId.isBlank()) {
            return true;
        }
        return path.getFileName().toString().startsWith(userId);
    }
}
