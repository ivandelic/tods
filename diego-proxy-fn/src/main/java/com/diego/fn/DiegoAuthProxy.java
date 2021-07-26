package com.diego.fn;

import java.io.ByteArrayOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class DiegoAuthProxy {

    public String handleRequest(String input) {
        String tokenUrl = System.getenv("TOKEN_URL");
        String serviceUrl = System.getenv("SERVICE_URL");
        String username = System.getenv("USERNAME");
        String password = System.getenv("PASSWORD");
        String clientCredentials = new String(Base64.getEncoder().encode(new String(System.getenv("CLIENT_ID") + ":" + System.getenv("CLIENT_SECRET")).getBytes()));
        String scope = System.getenv("SCOPE");
        
        String tokenResponse = retriveAccessToken(tokenUrl, username, password, scope, clientCredentials);
        String accessToken = extractAccessToken(tokenResponse);
        String serviceResponse = retriveService(serviceUrl, accessToken);

        return "{\"access_token\": \"" + accessToken + "\", \"external_service_payload\": \"" + serviceResponse + "\"}";
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

    private String retriveService(String url, String token) {
        String response = "";

        try {
            HttpURLConnection httpConn = (HttpURLConnection) new URL(url).openConnection();
            httpConn.setUseCaches(false);
            httpConn.setDoOutput(true);
            httpConn.setRequestMethod("GET");
            httpConn.setRequestProperty("Authorization", "Bearer " + token);
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