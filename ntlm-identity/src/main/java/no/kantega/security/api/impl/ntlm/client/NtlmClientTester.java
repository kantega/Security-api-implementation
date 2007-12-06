package no.kantega.security.api.impl.ntlm.client;

import java.net.HttpURLConnection;
import java.net.URL;
import java.net.MalformedURLException;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Iterator;

public class NtlmClientTester {
    private int iterations;
    private URL url;
    private int threads;

    public NtlmClientTester(URL url, int threads, int iterations) {
        this.url = url;
        this.threads = threads;
        this.iterations = iterations;
    }

    public static void main(String[] args) throws MalformedURLException {
        URL url = new URL(args[0]);
        int threads = Integer.parseInt(args[1]);
        int iterations = Integer.parseInt(args[2]);

        new NtlmClientTester(url, threads, iterations).run();

    }

    private void run() {
        for(int i = 0; i < threads; i++) {
            new Thread(new TestRunner(iterations, url)).start();
        }
    }

    class TestRunner implements Runnable {
        int iterations;
        URL url;
        TestRunner(int iterations, URL url) {
            this.iterations = iterations;
            this.url = url;
        }

        public void run() {
            for(int i = 0; i < iterations; i++) {
                try {
                    HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
                    urlConnection.setInstanceFollowRedirects(false);
                    urlConnection.connect();
                    int code = urlConnection.getResponseCode();
                    String message = urlConnection.getResponseMessage();
                    System.out.println("Code: " + code + ": " + message);
                    /**
                    Map<String,List<String>> headers = urlConnection.getHeaderFields();
                    for(String key : headers.keySet()) {
                        System.out.println(key +": " + headers.get(key));
                    } */
                    urlConnection.disconnect();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
