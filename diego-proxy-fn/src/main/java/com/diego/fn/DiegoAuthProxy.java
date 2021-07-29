package com.diego.fn;

import java.io.ByteArrayOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fnproject.fn.api.httpgateway.HTTPGatewayContext;

public class DiegoAuthProxy {

    private static final String DEFAULT_SERVICE_METHOD = "POST";

    private static final String PAYLOAD_JSON = "payload";
    private static final String PASSWORD_JSON = "password";
    private static final String USERNAME_JSON = "username";
    private static final String SERVICE_METHOD_JSON = "service-method";
    private static final String SERVICE_URL_JSON = "service-url";
    private static final String TOKEN_URL_JSON = "token-url";

    private static final String SCOPE = "SCOPE";
    private static final String CLIENT_SECRET = "CLIENT_SECRET";
    private static final String CLIENT_ID = "CLIENT_ID";
    private static final String PASSWORD = "PASSWORD";
    private static final String USERNAME = "USERNAME";
    private static final String SERVICE_URL = "SERVICE_URL";
    private static final String TOKEN_URL = "TOKEN_URL";

    public String handleRequest(HTTPGatewayContext hctx, String rawInput) {

        ObjectMapper mapper = new ObjectMapper();
        JsonNode input = mapper.createObjectNode();
        try {
            input = new ObjectMapper().readTree(rawInput);
        }
        catch (Exception e) {
            e.printStackTrace(); // not valid input json
        }

        String tokenUrl = !input.isEmpty() && input.has(TOKEN_URL_JSON) ? input.get(TOKEN_URL_JSON).asText() : System.getenv(TOKEN_URL);
        String serviceUrl = !input.isEmpty() && input.has(SERVICE_URL_JSON) ? input.get(SERVICE_URL_JSON).asText() : System.getenv(SERVICE_URL);
        String serviceMethod = !input.isEmpty() && input.has(SERVICE_METHOD_JSON) ? input.get(SERVICE_METHOD_JSON).asText() : DEFAULT_SERVICE_METHOD;
        String username = !input.isEmpty() && input.has(USERNAME_JSON) ? input.get(USERNAME_JSON).asText() : System.getenv(USERNAME);
        String password = !input.isEmpty() && input.has(PASSWORD_JSON) ? input.get(PASSWORD_JSON).asText() : System.getenv(PASSWORD);
        String clientCredentials = new String(Base64.getEncoder().encode(new String(System.getenv(CLIENT_ID) + ":" + System.getenv(CLIENT_SECRET)).getBytes()));
        String scope = System.getenv(SCOPE);

        String querystring = extractQuerystring(hctx.getRequestURL());
        String payload = !input.isEmpty() && input.has(PAYLOAD_JSON) ? input.get(PAYLOAD_JSON).asText() : null;

        String tokenResponse = retriveAccessToken(tokenUrl, username, password, scope, clientCredentials);
        String accessToken = extractAccessToken(tokenResponse);
        String serviceResponse = retriveService(serviceUrl, accessToken, serviceMethod, querystring, payload);

        return "{\"access_token\": \"" + accessToken + "\", \"external_service_payload\": \"" + serviceResponse + "\", \"input\": \"" + input.toString() + "\", \"querystring\": \"" + querystring + "\"}";
    }

    private String extractQuerystring(String requestUrl) {
        if (requestUrl == null || requestUrl.isEmpty() || !requestUrl.contains("?")) {
            return "";
        }
        return requestUrl.substring(requestUrl.indexOf("?"));
    }

    private String retriveAccessToken(String url, String username,String password, String scope, String clientCredentials) {
        String response = "";

        String urlParameters = "grant_type=password&username=" + username +"&password=" + password + "&scope=" + scope;
        byte[] postData = urlParameters.getBytes(StandardCharsets.UTF_8);

        try {
            HttpURLConnection httpConn = (HttpURLConnection) new URL(url).openConnection();
            httpConn.setUseCaches(false);
            httpConn.setDoOutput(true);
            httpConn.setRequestMethod("POST");
            httpConn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            httpConn.setRequestProperty("Content-Length", Integer.toString(postData.length));
            httpConn.setRequestProperty("Authorization", "Basic " + clientCredentials);
            httpConn.getOutputStream().write(postData);
            if (HttpURLConnection.HTTP_OK == httpConn.getResponseCode()) {
                ByteArrayOutputStream result = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int length;
                while ((length = httpConn.getInputStream().read(buffer)) != -1) {
                    result.write(buffer, 0, length);
                }
                response = result.toString(StandardCharsets.UTF_8);
                httpConn.disconnect();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return response;
    }

    private String retriveService(String url, String token, String serviceMethod, String querystring, String payload) {
        String response = "";

        try {
            HttpURLConnection httpConn = (HttpURLConnection) new URL(url).openConnection();
            httpConn.setUseCaches(false);
            httpConn.setDoOutput(true);
            httpConn.setRequestMethod(serviceMethod);
            httpConn.setRequestProperty("Content-Type", "application/json");
            httpConn.setRequestProperty("Authorization", "Bearer " + token);
            if (payload != null) {
                httpConn.getOutputStream().write(payload.getBytes(StandardCharsets.UTF_8));
            }
            if (HttpURLConnection.HTTP_OK == httpConn.getResponseCode()) {
                ByteArrayOutputStream result = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int length;
                while ((length = httpConn.getInputStream().read(buffer)) != -1) {
                    result.write(buffer, 0, length);
                }
                response = result.toString(StandardCharsets.UTF_8);
                httpConn.disconnect();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return response;
    }

    private String extractAccessToken(String tokenJson) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode rootNode = mapper.readTree(tokenJson);
            JsonNode accessTokenNode = rootNode.get("access_token");
            return accessTokenNode.textValue();
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }
}