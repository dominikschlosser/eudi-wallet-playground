package de.arbeitsagentur.keycloak.wallet.common.storage;

import de.arbeitsagentur.keycloak.wallet.issuance.config.WalletProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Component
public class CredentialStore {
    public static final String MOCK_ISSUER_OWNER = "mock-issuer";
    private final WalletProperties properties;
    private final ObjectMapper objectMapper;

    public CredentialStore(WalletProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    public synchronized Path saveCredential(String userId, Object credential) {
        try {
            Files.createDirectories(properties.storageDir());
            String safeUser = safeUser(userId);
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
        if (userId == null || userId.isBlank()) {
            return listAllEntries();
        }
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

    public synchronized List<Entry> listCredentialEntries(List<String> userIds) {
        if (userIds == null || userIds.isEmpty()) {
            return List.of();
        }
        Set<String> allowed = new HashSet<>();
        for (String id : userIds) {
            if (id != null && !id.isBlank()) {
                allowed.add(safeUser(id));
            }
        }
        if (allowed.isEmpty()) {
            return List.of();
        }
        List<Entry> items = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        try {
            for (Path path : listFiles()) {
                String fileName = path.getFileName().toString();
                if (allowed.stream().noneMatch(id -> fileName.startsWith(id + "-"))) {
                    continue;
                }
                if (!seen.add(fileName)) {
                    continue;
                }
                try {
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
        if (userId == null || userId.isBlank()) {
            return false;
        }
        String safeUser = safeUser(userId);
        Path target = properties.storageDir().resolve(fileName);
        if (!Files.exists(target)) {
            return false;
        }
        if (!fileName.startsWith(safeUser + "-")) {
            return false;
        }
        try {
            Files.deleteIfExists(target);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public synchronized boolean deleteCredential(List<String> userIds, String fileName) {
        if (fileName == null || fileName.isBlank()) {
            return false;
        }
        if (userIds == null || userIds.isEmpty()) {
            return false;
        }
        Set<String> allowed = new HashSet<>();
        for (String id : userIds) {
            if (id != null && !id.isBlank()) {
                allowed.add(safeUser(id));
            }
        }
        if (allowed.isEmpty()) {
            return false;
        }
        Path target = properties.storageDir().resolve(fileName);
        if (!Files.exists(target)) {
            return false;
        }
        boolean permitted = allowed.stream().anyMatch(id -> fileName.startsWith(id + "-"));
        if (!permitted) {
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
        String safeUser = safeUser(userId);
        return path.getFileName().toString().startsWith(safeUser + "-");
    }

    private List<Entry> listAllEntries() {
        try {
            List<Entry> items = new ArrayList<>();
            for (Path path : listFiles()) {
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

    private String safeUser(String userId) {
        if (userId == null || userId.isBlank()) {
            return "anon";
        }
        return userId.replaceAll("[^a-zA-Z0-9_-]", "_");
    }
}
