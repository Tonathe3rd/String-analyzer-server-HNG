import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import java.util.logging.Level;

public class StringAnalyzerServer {

    private static final Logger logger = Logger.getLogger(StringAnalyzerServer.class.getName());
    private static final Map<String, AnalyzedString> database = new ConcurrentHashMap<>();

    public static void main(String[] args) throws IOException {
        int port = 8080;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/strings", new StringHandler());
        server.createContext("/strings/filter-by-natural-language", new NaturalLanguageHandler());

        server.setExecutor(null);
        logger.info("🚀 Server started on http://localhost:" + port);
        server.start();
    }

    // Model for storing analyzed string
    static class AnalyzedString {
        String id;
        String value;
        Map<String, Object> properties;
        String createdAt;
    }

    static class StringHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                String method = exchange.getRequestMethod();
                URI uri = exchange.getRequestURI();
                String path = uri.getPath();
                String[] parts = path.split("/");

                if (method.equalsIgnoreCase("POST") && parts.length == 2) {
                    handlePost(exchange);
                } else if (method.equalsIgnoreCase("GET") && parts.length == 3) {
                    handleGetSpecific(exchange, parts[2]);
                } else if (method.equalsIgnoreCase("GET") && parts.length == 2) {
                    handleGetAll(exchange);
                } else if (method.equalsIgnoreCase("DELETE") && parts.length == 3) {
                    handleDelete(exchange, parts[2]);
                } else {
                    sendJson(exchange, 404, "{\"error\": \"Endpoint not found\"}");
                }

            } catch (Exception e) {
                logger.log(Level.SEVERE, "Internal server error", e);
                sendJson(exchange, 500, "{\"error\": \"Internal Server Error\"}");
            }
        }

        private void handlePost(HttpExchange exchange) throws IOException {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            if (body == null || body.isEmpty() || !body.contains("\"value\"")) {
                sendJson(exchange, 400, "{\"error\": \"Missing 'value' field\"}");
                return;
            }

            String value = body.replaceAll(".*\"value\"\\s*:\\s*\"([^\"]+)\".*", "$1").trim();

            if (value.isEmpty()) {
                sendJson(exchange, 400, "{\"error\": \"Empty 'value' field\"}");
                return;
            }

            // Compute hash
            String hash = sha256(value);

            if (database.containsKey(hash)) {
                sendJson(exchange, 409, "{\"error\": \"String already exists\"}");
                return;
            }

            Map<String, Object> props = computeProperties(value, hash);

            AnalyzedString analyzed = new AnalyzedString();
            analyzed.id = hash;
            analyzed.value = value;
            analyzed.properties = props;
            analyzed.createdAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now());

            database.put(hash, analyzed);

            String response = toJson(analyzed);
            sendJson(exchange, 201, response);
        }

        private void handleGetSpecific(HttpExchange exchange, String value) throws IOException {
            String hash = sha256(value);
            AnalyzedString analyzed = database.get(hash);
            if (analyzed == null) {
                sendJson(exchange, 404, "{\"error\": \"String not found\"}");
                return;
            }
            sendJson(exchange, 200, toJson(analyzed));
        }

        private void handleGetAll(HttpExchange exchange) throws IOException {
            Map<String, String> params = parseQuery(exchange.getRequestURI().getQuery());
            List<AnalyzedString> results = new ArrayList<>(database.values());

            results = applyFilters(results, params);

            StringBuilder sb = new StringBuilder();
            sb.append("{\"data\":[");
            for (int i = 0; i < results.size(); i++) {
                sb.append(toJson(results.get(i)));
                if (i < results.size() - 1) sb.append(",");
            }
            sb.append("],");
            sb.append("\"count\":").append(results.size()).append(",");
            sb.append("\"filters_applied\":").append(mapToJson(params)).append("}");

            sendJson(exchange, 200, sb.toString());
        }

        private void handleDelete(HttpExchange exchange, String value) throws IOException {
            String hash = sha256(value);
            if (database.remove(hash) != null) {
                exchange.sendResponseHeaders(204, -1);
            } else {
                sendJson(exchange, 404, "{\"error\": \"String not found\"}");
            }
        }

        private Map<String, Object> computeProperties(String value, String hash) {
            Map<String, Object> props = new LinkedHashMap<>();
            props.put("length", value.length());
            props.put("is_palindrome", isPalindrome(value));
            props.put("unique_characters", (int) value.chars().distinct().count());
            props.put("word_count", value.trim().split("\\s+").length);
            props.put("sha256_hash", hash);

            Map<String, Integer> freq = new LinkedHashMap<>();
            for (char c : value.toCharArray()) {
                freq.put(String.valueOf(c), freq.getOrDefault(String.valueOf(c), 0) + 1);
            }
            props.put("character_frequency_map", freq);
            return props;
        }

        private boolean isPalindrome(String s) {
            String lower = s.replaceAll("\\s+", "").toLowerCase();
            return lower.equals(new StringBuilder(lower).reverse().toString());
        }

        private String sha256(String input) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
                StringBuilder hex = new StringBuilder();
                for (byte b : hashBytes) hex.append(String.format("%02x", b));
                return hex.toString();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        private Map<String, String> parseQuery(String query) {
            Map<String, String> map = new LinkedHashMap<>();
            if (query == null) return map;
            for (String param : query.split("&")) {
                String[] pair = param.split("=");
                if (pair.length == 2) map.put(pair[0], pair[1]);
            }
            return map;
        }

        private List<AnalyzedString> applyFilters(List<AnalyzedString> data, Map<String, String> filters) {
            List<AnalyzedString> filtered = new ArrayList<>();
            for (AnalyzedString s : data) {
                Map<String, Object> p = s.properties;
                boolean match = true;
                for (Map.Entry<String, String> f : filters.entrySet()) {
                    switch (f.getKey()) {
                        case "is_palindrome" -> match &= p.get("is_palindrome").toString().equalsIgnoreCase(f.getValue());
                        case "min_length" -> match &= (int) p.get("length") >= Integer.parseInt(f.getValue());
                        case "max_length" -> match &= (int) p.get("length") <= Integer.parseInt(f.getValue());
                        case "word_count" -> match &= (int) p.get("word_count") == Integer.parseInt(f.getValue());
                        case "contains_character" -> match &= s.value.contains(f.getValue());
                    }
                }
                if (match) filtered.add(s);
            }
            return filtered;
        }

        private String toJson(AnalyzedString analyzed) {
            return String.format(
                    "{\"id\":\"%s\",\"value\":\"%s\",\"properties\":%s,\"created_at\":\"%s\"}",
                    analyzed.id, analyzed.value, mapToJson(analyzed.properties), analyzed.createdAt
            );
        }

        private String mapToJson(Map<?, ?> map) {
            StringBuilder sb = new StringBuilder("{");
            Iterator<? extends Map.Entry<?, ?>> it = map.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<?, ?> e = it.next();
                sb.append("\"").append(e.getKey()).append("\":");
                if (e.getValue() instanceof Map) sb.append(mapToJson((Map<?, ?>) e.getValue()));
                else if (e.getValue() instanceof String) sb.append("\"").append(e.getValue()).append("\"");
                else sb.append(e.getValue());
                if (it.hasNext()) sb.append(",");
            }
            sb.append("}");
            return sb.toString();
        }

        private void sendJson(HttpExchange exchange, int statusCode, String json) throws IOException {
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(statusCode, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }

    static class NaturalLanguageHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            if (query == null || !query.contains("query=")) {
                sendJson(exchange, 400, "{\"error\":\"Missing query parameter\"}");
                return;
            }

            String naturalQuery = query.replaceFirst("query=", "").replace("%20", " ");
            Map<String, String> filters = new LinkedHashMap<>();

            if (naturalQuery.contains("single word")) filters.put("word_count", "1");
            if (naturalQuery.contains("palindromic")) filters.put("is_palindrome", "true");
            if (naturalQuery.contains("longer than")) {
                String[] parts = naturalQuery.split("longer than ");
                filters.put("min_length", String.valueOf(Integer.parseInt(parts[1].split(" ")[0]) + 1));
            }
            if (naturalQuery.contains("containing the letter")) {
                String letter = naturalQuery.split("containing the letter ")[1].trim();
                filters.put("contains_character", letter);
            }

            List<AnalyzedString> results = new ArrayList<>(database.values());
            results = new StringHandler().applyFilters(results, filters);

            StringBuilder sb = new StringBuilder();
            sb.append("{\"data\":[");
            for (int i = 0; i < results.size(); i++) {
                sb.append(new StringHandler().toJson(results.get(i)));
                if (i < results.size() - 1) sb.append(",");
            }
            sb.append("],");
            sb.append("\"count\":").append(results.size()).append(",");
            sb.append("\"interpreted_query\":");
            sb.append("{\"original\":\"").append(naturalQuery).append("\",\"parsed_filters\":").append(mapToJson(filters)).append("}}");

            sendJson(exchange, 200, sb.toString());
        }

        private static void sendJson(HttpExchange exchange, int statusCode, String json) throws IOException {
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(statusCode, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }

        private static String mapToJson(Map<?, ?> map) {
            StringBuilder sb = new StringBuilder("{");
            Iterator<? extends Map.Entry<?, ?>> it = map.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<?, ?> e = it.next();
                sb.append("\"").append(e.getKey()).append("\":\"").append(e.getValue()).append("\"");
                if (it.hasNext()) sb.append(",");
            }
            sb.append("}");
            return sb.toString();
        }
    }
}
