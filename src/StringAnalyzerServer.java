// StringAnalyzerServer.java
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.logging.Logger;
import java.util.logging.Level;

public class StringAnalyzerServer {

    private static final Logger logger = Logger.getLogger(StringAnalyzerServer.class.getName());

    // In-memory store: sha256 -> StoredString
    private static final ConcurrentMap<String, StoredString> store = new ConcurrentHashMap<>();

    // Also keep map from original value to sha (for quick lookup by string value)
    private static final ConcurrentMap<String, String> valueToHash = new ConcurrentHashMap<>();

    public static void main(String[] args) throws Exception {
        int port = 8080;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/strings", new StringsHandler());
        server.createContext("/strings/filter-by-natural-language", new NaturalLanguageFilterHandler());

        // root info
        server.createContext("/", exchange -> {
            String resp = "String Analyzer API. Use POST /strings to add, GET /strings to list, GET /strings/{value} to retrieve.";
            exchange.sendResponseHeaders(200, resp.getBytes(StandardCharsets.UTF_8).length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(resp.getBytes(StandardCharsets.UTF_8));
            }
        });

        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();
        logger.info("Server started on http://localhost:" + port);
    }

    /* ----- Data model ----- */
    static class StoredString {
        final String id; // sha256
        final String value;
        final Map<String, Object> properties;
        final String createdAt;

        StoredString(String id, String value, Map<String, Object> properties, String createdAt) {
            this.id = id;
            this.value = value;
            this.properties = properties;
            this.createdAt = createdAt;
        }

        String toJson() {
            return toJsonObject(this);
        }
    }

    /* ----- Handlers ----- */

    static class StringsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                String method = exchange.getRequestMethod();
                String path = exchange.getRequestURI().getPath();
                String rawQuery = exchange.getRequestURI().getRawQuery();

                // Path could be /strings or /strings/{value}
                String[] parts = path.split("/", 3); // ["", "strings", maybe value]
                if ("POST".equalsIgnoreCase(method) && parts.length == 2) {
                    handlePost(exchange);
                } else if ("GET".equalsIgnoreCase(method) && parts.length == 3) {
                    // GET /strings/{string_value}
                    String encodedValue = parts[2];
                    String value = urlDecode(encodedValue);
                    handleGetSingle(exchange, value);
                } else if ("GET".equalsIgnoreCase(method) && parts.length == 2) {
                    // GET /strings?...
                    handleGetAll(exchange, rawQuery);
                } else if ("DELETE".equalsIgnoreCase(method) && parts.length == 3) {
                    String encodedValue = parts[2];
                    String value = urlDecode(encodedValue);
                    handleDelete(exchange, value);
                } else {
                    sendJson(exchange, 404, jsonError("Not Found"));
                }
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Handler error", e);
                sendJson(exchange, 500, jsonError("Internal server error"));
            }
        }

        /* POST /strings */
        private void handlePost(HttpExchange exchange) throws IOException {
            String body = readRequestBody(exchange);
            if (body == null || body.trim().isEmpty()) {
                sendJson(exchange, 400, jsonError("Invalid request body or missing \"value\" field"));
                return;
            }

            // naive JSON extraction of "value": "..."
            String value;
            try {
                value = extractJsonStringField(body, "value");
            } catch (IllegalArgumentException e) {
                sendJson(exchange, 422, jsonError("Invalid data type for \"value\" (must be string)"));
                return;
            }

            if (value == null) {
                sendJson(exchange, 400, jsonError("Invalid request body or missing \"value\" field"));
                return;
            }

            String sha = sha256(value);
            if (store.containsKey(sha)) {
                sendJson(exchange, 409, jsonError("String already exists in the system"));
                return;
            }

            Map<String, Object> props = computeProperties(value, sha);
            String createdAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
            StoredString ss = new StoredString(sha, value, props, createdAt);

            store.put(sha, ss);
            valueToHash.put(value, sha);

            String json = ss.toJson();
            sendJson(exchange, 201, json);
        }

        /* GET /strings/{value} */
        private void handleGetSingle(HttpExchange exchange, String value) throws IOException {
            if (value == null) {
                sendJson(exchange, 400, jsonError("Missing string value"));
                return;
            }
            String sha = sha256(value);
            StoredString ss = store.get(sha);
            if (ss == null) {
                sendJson(exchange, 404, jsonError("String does not exist in the system"));
                return;
            }
            sendJson(exchange, 200, ss.toJson());
        }

        /* GET /strings?filters... */
        private void handleGetAll(HttpExchange exchange, String rawQuery) throws IOException {
            // parse query params
            Map<String, String> qp = parseQuery(rawQuery);
            // validate and convert
            Boolean isPal = parseBoolean(qp.get("is_palindrome"));
            Integer minLen = parseInteger(qp.get("min_length"));
            Integer maxLen = parseInteger(qp.get("max_length"));
            Integer wordCount = parseInteger(qp.get("word_count"));
            String containsChar = qp.get("contains_character");
            if (containsChar != null && containsChar.length() > 1) {
                sendJson(exchange, 400, jsonError("contains_character must be a single character"));
                return;
            }

            List<StoredString> results = new ArrayList<>();
            for (StoredString ss : store.values()) {
                Map<String, Object> p = ss.properties;
                int length = ((Number) p.get("length")).intValue();
                boolean pal = (Boolean) p.get("is_palindrome");
                int wc = ((Number) p.get("word_count")).intValue();

                if (isPal != null && pal != isPal) continue;
                if (minLen != null && length < minLen) continue;
                if (maxLen != null && length > maxLen) continue;
                if (wordCount != null && wc != wordCount) continue;
                if (containsChar != null) {
                    // check character frequency map; consider literal character
                    Map<String, Integer> freq = (Map<String, Integer>) p.get("character_frequency_map");
                    if (!freq.containsKey(containsChar)) continue;
                }
                results.add(ss);
            }

            // build response
            StringBuilder sb = new StringBuilder();
            sb.append("{\n  \"data\": [\n");
            for (int i = 0; i < results.size(); i++) {
                sb.append("    ").append(results.get(i).toJson());
                if (i < results.size() - 1) sb.append(",");
                sb.append("\n");
            }
            sb.append("  ],\n");
            sb.append("  \"count\": ").append(results.size()).append(",\n");
            sb.append("  \"filters_applied\": ").append(buildFiltersObject(qp)).append("\n");
            sb.append("}");
            sendJson(exchange, 200, sb.toString());
        }

        /* DELETE /strings/{value} */
        private void handleDelete(HttpExchange exchange, String value) throws IOException {
            String sha = sha256(value);
            StoredString ss = store.remove(sha);
            if (ss == null) {
                sendJson(exchange, 404, jsonError("String does not exist in the system"));
                return;
            }
            valueToHash.remove(ss.value);
            // 204 No Content
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        }
    }

    /* Natural language filter handler */
    static class NaturalLanguageFilterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                String rawQuery = exchange.getRequestURI().getRawQuery();
                Map<String, String> qp = parseQuery(rawQuery);
                String q = qp.get("query");
                if (q == null || q.trim().isEmpty()) {
                    sendJson(exchange, 400, jsonError("Missing query parameter"));
                    return;
                }
                String decoded = urlDecode(q).toLowerCase();

                // simple parsing heuristics
                Map<String, Object> parsedFilters = new HashMap<>();
                if (decoded.contains("single word")) parsedFilters.put("word_count", 1);
                if (decoded.contains("palindrome") || decoded.contains("palindrome")) parsedFilters.put("is_palindrome", true);

                // "longer than N characters" e.g., "longer than 10 characters"
                Matcher m = Pattern.compile("longer than (\\d+)").matcher(decoded);
                if (m.find()) {
                    int n = Integer.parseInt(m.group(1));
                    parsedFilters.put("min_length", n + 1);
                }

                // "strings containing the letter z" or "containing the letter z"
                m = Pattern.compile("letter ([a-z0-9])").matcher(decoded);
                if (m.find()) parsedFilters.put("contains_character", m.group(1));

                // "strings containing the letter z" fallback: "containing the letter z"
                m = Pattern.compile("containing the letter ([a-z0-9])").matcher(decoded);
                if (m.find()) parsedFilters.put("contains_character", m.group(1));

                if (parsedFilters.isEmpty()) {
                    sendJson(exchange, 400, jsonError("Unable to parse natural language query"));
                    return;
                }

                // apply parsed filters to store
                List<StoredString> results = new ArrayList<>();
                for (StoredString ss : store.values()) {
                    Map<String, Object> p = ss.properties;
                    boolean ok = true;
                    if (parsedFilters.containsKey("is_palindrome")) {
                        boolean val = (Boolean) parsedFilters.get("is_palindrome");
                        if (val != (Boolean) p.get("is_palindrome")) ok = false;
                    }
                    if (parsedFilters.containsKey("word_count")) {
                        if (((Number) p.get("word_count")).intValue() != (Integer) parsedFilters.get("word_count")) ok = false;
                    }
                    if (parsedFilters.containsKey("min_length")) {
                        if (((Number) p.get("length")).intValue() < (Integer) parsedFilters.get("min_length")) ok = false;
                    }
                    if (parsedFilters.containsKey("contains_character")) {
                        String ch = (String) parsedFilters.get("contains_character");
                        Map<String, Integer> freq = (Map<String, Integer>) p.get("character_frequency_map");
                        if (!freq.containsKey(ch)) ok = false;
                    }
                    if (ok) results.add(ss);
                }

                // build response
                StringBuilder sb = new StringBuilder();
                sb.append("{\n  \"data\": [\n");
                for (int i = 0; i < results.size(); i++) {
                    sb.append("    ").append(results.get(i).toJson());
                    if (i < results.size() - 1) sb.append(",");
                    sb.append("\n");
                }
                sb.append("  ],\n");
                sb.append("  \"count\": ").append(results.size()).append(",\n");
                sb.append("  \"interpreted_query\": {\n");
                sb.append("    \"original\": \"").append(escapeJsonForSimple(decoded)).append("\",\n");
                sb.append("    \"parsed_filters\": ").append(mapToJson(parsedFilters)).append("\n");
                sb.append("  }\n");
                sb.append("}");
                sendJson(exchange, 200, sb.toString());

            } catch (Exception e) {
                logger.log(Level.SEVERE, "NL handler error", e);
                sendJson(exchange, 500, jsonError("Internal server error"));
            }
        }
    }

    /* ----- Utilities ----- */

    private static Map<String, Object> computeProperties(String value, String sha) {
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("length", value.length());
        props.put("is_palindrome", isPalindromeNormalized(value));
        props.put("unique_characters", uniqueCharCount(value));
        props.put("word_count", wordCount(value));
        props.put("sha256_hash", sha);
        props.put("character_frequency_map", characterFrequencyMap(value));
        return props;
    }

    private static boolean isPalindromeNormalized(String s) {
        // case-insensitive, ignore non-alphanumeric and whitespace
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (Character.isLetterOrDigit(c)) sb.append(Character.toLowerCase(c));
        }
        String clean = sb.toString();
        String rev = sb.reverse().toString();
        return clean.equals(rev);
    }

    private static int uniqueCharCount(String s) {
        Set<Character> set = new HashSet<>();
        for (char c : s.toCharArray()) set.add(c);
        return set.size();
    }

    private static int wordCount(String s) {
        String trimmed = s.trim();
        if (trimmed.isEmpty()) return 0;
        String[] parts = trimmed.split("\\s+");
        return parts.length;
    }

    private static Map<String, Integer> characterFrequencyMap(String s) {
        Map<String, Integer> freq = new LinkedHashMap<>();
        for (char c : s.toCharArray()) {
            String key = String.valueOf(c);
            freq.put(key, freq.getOrDefault(key, 0) + 1);
        }
        return freq;
    }

    private static String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String readRequestBody(HttpExchange exchange) throws IOException {
        InputStream is = exchange.getRequestBody();
        if (is == null) return null;
        try (Scanner s = new Scanner(is, StandardCharsets.UTF_8.name())) {
            s.useDelimiter("\\A");
            return s.hasNext() ? s.next() : "";
        }
    }

    private static String extractJsonStringField(String json, String fieldName) {
        // naive but works for simple well-formed JSON: "fieldName": "value"
        Pattern p = Pattern.compile("\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*\"((?:\\\\\"|[^\"])*)\"", Pattern.DOTALL);
        Matcher m = p.matcher(json);
        if (!m.find()) return null;
        String raw = m.group(1);
        // unescape simple quotes and backslashes
        return raw.replace("\\\"", "\"").replace("\\\\", "\\");
    }

    private static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            return s;
        }
    }

    private static Map<String, String> parseQuery(String rawQuery) {
        Map<String, String> m = new LinkedHashMap<>();
        if (rawQuery == null || rawQuery.trim().isEmpty()) return m;
        String[] pairs = rawQuery.split("&");
        for (String p : pairs) {
            int idx = p.indexOf('=');
            if (idx == -1) continue;
            String k = urlDecode(p.substring(0, idx));
            String v = urlDecode(p.substring(idx + 1));
            m.put(k, v);
        }
        return m;
    }

    private static Boolean parseBoolean(String s) {
        if (s == null) return null;
        if ("true".equalsIgnoreCase(s) || "1".equals(s)) return true;
        if ("false".equalsIgnoreCase(s) || "0".equals(s)) return false;
        return null;
    }

    private static Integer parseInteger(String s) {
        if (s == null) return null;
        try { return Integer.parseInt(s); } catch (NumberFormatException e) { return null; }
    }

    private static String jsonError(String message) {
        return "{\"error\": \"" + escapeJsonForSimple(message) + "\"}";
    }

    private static String escapeJsonForSimple(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\r", "");
    }

    private static String toJsonObject(StoredString ss) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"id\": \"").append(ss.id).append("\",\n");
        sb.append("  \"value\": \"").append(escapeJsonForSimple(ss.value)).append("\",\n");
        sb.append("  \"properties\": ").append(mapToJson(ss.properties)).append(",\n");
        sb.append("  \"created_at\": \"").append(ss.createdAt).append("\"\n");
        sb.append("}");
        return sb.toString();
    }

    private static String mapToJson(Object obj) {
        if (obj == null) return "null";
        if (obj instanceof Map) {
            Map<?, ?> m = (Map<?, ?>) obj;
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) sb.append(", ");
                sb.append("\"").append(escapeJsonForSimple(String.valueOf(e.getKey()))).append("\": ");
                sb.append(mapToJson(e.getValue()));
                first = false;
            }
            sb.append("}");
            return sb.toString();
        } else if (obj instanceof String) {
            return "\"" + escapeJsonForSimple((String) obj) + "\"";
        } else if (obj instanceof Number || obj instanceof Boolean) {
            return String.valueOf(obj);
        } else if (obj instanceof Collection) {
            Collection<?> c = (Collection<?>) obj;
            StringBuilder sb = new StringBuilder();
            sb.append("[");
            boolean first = true;
            for (Object o : c) {
                if (!first) sb.append(", ");
                sb.append(mapToJson(o));
                first = false;
            }
            sb.append("]");
            return sb.toString();
        } else if (obj instanceof Map<?, ?>) {
            return mapToJson((Map<?, ?>) obj);
        } else {
            return "\"" + escapeJsonForSimple(String.valueOf(obj)) + "\"";
        }
    }

    private static String buildFiltersObject(Map<String, String> qp) {
        if (qp == null || qp.isEmpty()) return "{}";
        Map<String, Object> m = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : qp.entrySet()) {
            String k = e.getKey();
            String v = e.getValue();
            // try types
            if ("is_palindrome".equals(k)) {
                Boolean b = parseBoolean(v);
                m.put(k, b == null ? v : b);
            } else if ("min_length".equals(k) || "max_length".equals(k) || "word_count".equals(k)) {
                Integer iv = parseInteger(v);
                m.put(k, iv == null ? v : iv);
            } else {
                m.put(k, v);
            }
        }
        return mapToJson(m);
    }
}
