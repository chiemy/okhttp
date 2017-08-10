/*
 * Copyright (C) 2016 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package okhttp3.internal.http;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.HttpRetryException;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.SocketTimeoutException;
import java.security.cert.CertificateException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocketFactory;

import okhttp3.Address;
import okhttp3.Call;
import okhttp3.CertificatePinner;
import okhttp3.Connection;
import okhttp3.EventListener;
import okhttp3.HttpUrl;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.Route;
import okhttp3.internal.connection.RouteException;
import okhttp3.internal.connection.StreamAllocation;
import okhttp3.internal.http2.ConnectionShutdownException;

import static java.net.HttpURLConnection.HTTP_CLIENT_TIMEOUT;
import static java.net.HttpURLConnection.HTTP_MOVED_PERM;
import static java.net.HttpURLConnection.HTTP_MOVED_TEMP;
import static java.net.HttpURLConnection.HTTP_MULT_CHOICE;
import static java.net.HttpURLConnection.HTTP_PROXY_AUTH;
import static java.net.HttpURLConnection.HTTP_SEE_OTHER;
import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;
import static okhttp3.internal.Util.closeQuietly;
import static okhttp3.internal.http.StatusLine.HTTP_PERM_REDIRECT;
import static okhttp3.internal.http.StatusLine.HTTP_TEMP_REDIRECT;

/**
 * This interceptor recovers from failures and follows redirects as necessary. It may throw an
 * {@link IOException} if the call was canceled.
 * <br>错误重试、重定向
 */
public final class RetryAndFollowUpInterceptor implements Interceptor {
    /**
     * How many redirects and auth challenges should we attempt? Chrome follows 21 redirects; Firefox,
     * curl, and wget follow 20; Safari follows 16; and HTTP/1.0 recommends 5.
     */
    private static final int MAX_FOLLOW_UPS = 20;

    private final OkHttpClient client;
    private final boolean forWebSocket;
    private StreamAllocation streamAllocation;
    private Object callStackTrace;
    private volatile boolean canceled;

    public RetryAndFollowUpInterceptor(OkHttpClient client, boolean forWebSocket) {
        this.client = client;
        this.forWebSocket = forWebSocket;
    }

    /**
     * Immediately closes the socket connection if it's currently held. Use this to interrupt an
     * in-flight request from any thread. It's the caller's responsibility to close the request body
     * and response body streams; otherwise resources may be leaked.
     * <p>
     * <p>This method is safe to be called concurrently, but provides limited guarantees. If a
     * transport layer connection has been established (such as a HTTP/2 stream) that is terminated.
     * Otherwise if a socket connection is being established, that is terminated.
     */
    public void cancel() {
        canceled = true;
        StreamAllocation streamAllocation = this.streamAllocation;
        if (streamAllocation != null) streamAllocation.cancel();
    }

    public boolean isCanceled() {
        return canceled;
    }

    public void setCallStackTrace(Object callStackTrace) {
        this.callStackTrace = callStackTrace;
    }

    public StreamAllocation streamAllocation() {
        return streamAllocation;
    }

    /**
     * 主要逻辑伪码
     * <pre> {@code
     *
     *   Request request = chain.request();
     *   ...
     *   int followUpCount = 0;
     *   Response priorResponse = null;
     *
     *   //循环入口
     *   while (true) {
     *      ...
     *      Response response = null;
     *      try {
     *          //一次请求处理，获得结果
     *          response = ((RealInterceptorChain) chain).proceed(request, streamAllocation, null, null);
     *      } catch (RouteException e) {
     *          ...
     *          continue;
     *      } catch (IOException e) {
     *          ...
     *          continue;
     *      } finally {
     *          ...
     *      }
     *      // 如果前一次请求结果不为空，讲它添加到新的请求结果中。通常第一次请求一定是异常请求结果，一定没有body。
     *      if (priorResponse != null) {
     *          response = response.newBuilder()
     *                             .priorResponse(priorResponse.newBuilder()
     *                             .body(null)
     *                             .build())
     *                             .build();
     *      }
     *      //获取后续的请求，比如验证，重定向，失败重连...
     *      Request followUp = followUpRequest(response);
     *      if (followUp == null) {
     *          ...
     *          //如果没有后续的请求了，直接返回请求结果
     *          return response;
     *      }
     *      ...
     *      request = followUp;
     *      priorResponse = response;
     *  }
     * }</pre>
     */
    @Override
    public Response intercept(Chain chain) throws IOException {
        Request request = chain.request();
        RealInterceptorChain realChain = (RealInterceptorChain) chain;
        Call call = realChain.call();
        EventListener eventListener = realChain.eventListener();

        streamAllocation = new StreamAllocation(client.connectionPool(), createAddress(request.url()),
                call, eventListener, callStackTrace);

        int followUpCount = 0;
        Response priorResponse = null;
        while (true) {
            if (canceled) {
                streamAllocation.release();
                throw new IOException("Canceled");
            }

            Response response;
            boolean releaseConnection = true;
            try {
                response = realChain.proceed(request, streamAllocation, null, null);
                releaseConnection = false;
            } catch (RouteException e) {
                // The attempt to connect via a route failed. The request will not have been sent.
                // 尝试通过路由连接失败，请求还没有发出
                if (!recover(e.getLastConnectException(), false, request)) {
                    throw e.getLastConnectException();
                }
                releaseConnection = false;
                continue;
            } catch (IOException e) {
                // An attempt to communicate with a server failed. The request may have been sent.
                // 尝试与服务器通讯失败，请求可能已经发出
                boolean requestSendStarted = !(e instanceof ConnectionShutdownException);
                if (!recover(e, requestSendStarted, request)) throw e;
                releaseConnection = false;
                continue;
            } finally {
                // We're throwing an unchecked exception. Release any resources.
                // 抛出未捕获的异常，释放资源
                if (releaseConnection) {
                    streamAllocation.streamFailed(null);
                    streamAllocation.release();
                }
            }

            // Attach the prior response if it exists. Such responses never have a body.
            // 如果前一次请求结果不为空，将它添加到新的请求结果中。
            // 通常第一次请求一定是异常请求结果，一定没有body。
            if (priorResponse != null) {
                response = response.newBuilder()
                        .priorResponse(priorResponse.newBuilder()
                                .body(null)
                                .build())
                        .build();
            }
            // 继续请求，比如验证，重定向，失败重连.
            Request followUp = followUpRequest(response);

            // 不继续请求，则释放资源
            if (followUp == null) {
                if (!forWebSocket) {
                    streamAllocation.release();
                }
                return response;
            }
            // 关闭
            closeQuietly(response.body());

            if (++followUpCount > MAX_FOLLOW_UPS) {
                streamAllocation.release();
                throw new ProtocolException("Too many follow-up requests: " + followUpCount);
            }

            if (followUp.body() instanceof UnrepeatableRequestBody) {
                streamAllocation.release();
                throw new HttpRetryException("Cannot retry streamed HTTP body", response.code());
            }
            // 不是同一个连接，重新创建 StreamAllocation
            if (!sameConnection(response, followUp.url())) {
                streamAllocation.release();
                streamAllocation = new StreamAllocation(client.connectionPool(),
                        createAddress(followUp.url()), call, eventListener, callStackTrace);
            } else if (streamAllocation.codec() != null) {
                throw new IllegalStateException("Closing the body of " + response
                        + " didn't close its backing stream. Bad interceptor?");
            }

            request = followUp;
            priorResponse = response;
        }
    }

    private Address createAddress(HttpUrl url) {
        SSLSocketFactory sslSocketFactory = null;
        HostnameVerifier hostnameVerifier = null;
        CertificatePinner certificatePinner = null;
        if (url.isHttps()) {
            sslSocketFactory = client.sslSocketFactory();
            hostnameVerifier = client.hostnameVerifier();
            certificatePinner = client.certificatePinner();
        }

        return new Address(url.host(), url.port(), client.dns(), client.socketFactory(),
                sslSocketFactory, hostnameVerifier, certificatePinner, client.proxyAuthenticator(),
                client.proxy(), client.protocols(), client.connectionSpecs(), client.proxySelector());
    }

    /**
     * Report and attempt to recover from a failure to communicate with a server. Returns true if
     * {@code e} is recoverable, or false if the failure is permanent. Requests with a body can only
     * be recovered if the body is buffered or if the failure occurred before the request has been
     * sent.
     *<br>
     *     在服务器通讯失败的情况下，尝试重试，并返回重试的结果。
     *     如果可重试，返回 true，如果错误是永久性的，返回 false。
     *     有请求体的请求，只有当请求体是缓存的或者错误发生在请求发送前，才可重试
     */
    private boolean recover(IOException e, boolean requestSendStarted, Request userRequest) {
        streamAllocation.streamFailed(e);

        // The application layer has forbidden retries.
        // 应用没有配置连接失败后重试
        if (!client.retryOnConnectionFailure()) return false;

        // We can't send the request body again.
        // 请求体不能再次发送
        // 不是被 RouteException 包裹的异常，并且请求体被 UnrepeatableRequestBody 标记
        if (requestSendStarted && userRequest.body() instanceof UnrepeatableRequestBody) return false;

        // This exception is fatal.
        // 致命的异常，不可重试
        if (!isRecoverable(e, requestSendStarted)) return false;

        // No more routes to attempt.
        // 已经没有其他的路由可以使用
        if (!streamAllocation.hasMoreRoutes()) return false;

        // For failure recovery, use the same route selector with a new connection.
        return true;
    }

    private boolean isRecoverable(IOException e, boolean requestSendStarted) {
        // If there was a protocol problem, don't recover.
        // 协议异常不可重试
        if (e instanceof ProtocolException) {
            return false;
        }

        // If there was an interruption don't recover, but if there was a timeout connecting to a route
        // we should try the next route (if there is one).
        // 如果连接路由超时，则应该尝试下一个路由（如果有的话）
        if (e instanceof InterruptedIOException) {
            return e instanceof SocketTimeoutException && !requestSendStarted;
        }

        // Look for known client-side or negotiation errors that are unlikely to be fixed by trying
        // again with a different route.
        if (e instanceof SSLHandshakeException) {
            // If the problem was a CertificateException from the X509TrustManager,
            // do not retry.
            // 证书错误导致的异常，不重试
            if (e.getCause() instanceof CertificateException) {
                return false;
            }
        }

        // 证书不在可以信任的证书列表中
        if (e instanceof SSLPeerUnverifiedException) {
            // e.g. a certificate pinning error.
            return false;
        }

        // An example of one we might want to retry with a different route is a problem connecting to a
        // proxy and would manifest as a standard IOException. Unless it is one we know we should not
        // retry, we return true and try a new route.
        return true;
    }

    /**
     * Figures out the HTTP request to make in response to receiving {@code userResponse}. This will
     * either add authentication headers, follow redirects or handle a client request timeout. If a
     * follow-up is either unnecessary or not applicable, this returns null.
     */
    private Request followUpRequest(Response userResponse) throws IOException {
        if (userResponse == null) throw new IllegalStateException();
        Connection connection = streamAllocation.connection();
        Route route = connection != null
                ? connection.route()
                : null;
        int responseCode = userResponse.code();

        final String method = userResponse.request().method();
        switch (responseCode) {
            // 407 需要授权代理
            case HTTP_PROXY_AUTH:
                Proxy selectedProxy = route != null
                        ? route.proxy()
                        : client.proxy();
                if (selectedProxy.type() != Proxy.Type.HTTP) {
                    throw new ProtocolException("Received HTTP_PROXY_AUTH (407) code while not using proxy");
                }
                return client.proxyAuthenticator().authenticate(route, userResponse);
            // 401 未授权
            case HTTP_UNAUTHORIZED:
                return client.authenticator().authenticate(route, userResponse);

            // 308
            case HTTP_PERM_REDIRECT:
            // 307
            case HTTP_TEMP_REDIRECT:
                // "If the 307 or 308 status code is received in response to a request other than GET
                // or HEAD, the user agent MUST NOT automatically redirect the request"
                // 如果不是 GET 或 HEAD 请求，不能重定向
                if (!method.equals("GET") && !method.equals("HEAD")) {
                    return null;
                }
                // fall-through
            case HTTP_MULT_CHOICE: // 300
            case HTTP_MOVED_PERM: // 301
            case HTTP_MOVED_TEMP: // 302
            case HTTP_SEE_OTHER: // 303
                // Does the client allow redirects?
                // 是否设置允许重定向（默认为 false）
                if (!client.followRedirects()) return null;
                // 从响应中获取 Location
                String location = userResponse.header("Location");
                if (location == null) return null;
                HttpUrl url = userResponse.request().url().resolve(location);

                // Don't follow redirects to unsupported protocols.
                // 不支持的协议不重定向
                if (url == null) return null;

                // If configured, don't follow redirects between SSL and non-SSL.
                // HTTPS 和 HTTP 之间的重定向，需要根据配置 followSslRedirects(默认 true) 来判断
                boolean sameScheme = url.scheme().equals(userResponse.request().url().scheme());
                if (!sameScheme && !client.followSslRedirects()) return null;

                // Most redirects don't include a request body.
                Request.Builder requestBuilder = userResponse.request().newBuilder();
                if (HttpMethod.permitsRequestBody(method)) {
                    final boolean maintainBody = HttpMethod.redirectsWithBody(method);
                    if (HttpMethod.redirectsToGet(method)) {
                        requestBuilder.method("GET", null);
                    } else {
                        RequestBody requestBody = maintainBody ? userResponse.request().body() : null;
                        requestBuilder.method(method, requestBody);
                    }
                    if (!maintainBody) {
                        requestBuilder.removeHeader("Transfer-Encoding");
                        requestBuilder.removeHeader("Content-Length");
                        requestBuilder.removeHeader("Content-Type");
                    }
                }

                // When redirecting across hosts, drop all authentication headers. This
                // is potentially annoying to the application layer since they have no
                // way to retain them.
                // 如果不是同一个连接（比如 host 不同），去掉授权头部 “Authorization”
                if (!sameConnection(userResponse, url)) {
                    requestBuilder.removeHeader("Authorization");
                }

                return requestBuilder.url(url).build();

            case HTTP_CLIENT_TIMEOUT: // 408
                // 408's are rare in practice, but some servers like HAProxy use this response code. The
                // spec says that we may repeat the request without modifications. Modern browsers also
                // repeat the request (even non-idempotent ones.)
                // 实际情况下 408 很少出现，但有些服务端，如 HAProxy，使用 408。
                // 408 表示不修改原请求，再重新发送
                if (!client.retryOnConnectionFailure()) {
                    // The application layer has directed us not to retry the request.
                    // 应用层配置连接失败不需要重试
                    return null;
                }

                if (userResponse.request().body() instanceof UnrepeatableRequestBody) {
                    return null;
                }

                if (userResponse.priorResponse() != null
                        && userResponse.priorResponse().code() == HTTP_CLIENT_TIMEOUT) {
                    // We attempted to retry and got another timeout. Give up.
                    // 尝试重试了，但又超时了，放弃
                    return null;
                }

                return userResponse.request();

            default:
                return null;
        }
    }

    /**
     * Returns true if an HTTP request for {@code followUp} can reuse the connection used by this
     * engine.
     * <br>
     *     host 相同
     *     port 相同
     *     scheme 相同，http 或 https
     */
    private boolean sameConnection(Response response, HttpUrl followUp) {
        HttpUrl url = response.request().url();
        return url.host().equals(followUp.host())
                && url.port() == followUp.port()
                && url.scheme().equals(followUp.scheme());
    }
}
