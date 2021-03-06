/*
 * Copyright (C) 2015 Square, Inc.
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
package okhttp3.internal.connection;

import java.io.IOException;
import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
import java.net.Socket;
import java.util.List;

import okhttp3.Address;
import okhttp3.Call;
import okhttp3.Connection;
import okhttp3.ConnectionPool;
import okhttp3.EventListener;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Route;
import okhttp3.internal.Internal;
import okhttp3.internal.Util;
import okhttp3.internal.http.HttpCodec;
import okhttp3.internal.http2.ConnectionShutdownException;
import okhttp3.internal.http2.ErrorCode;
import okhttp3.internal.http2.StreamResetException;

import static okhttp3.internal.Util.closeQuietly;

/**
 * 用来协调 Connection，Stream 和 Calls 的关系。封装了网络连接创建的一些策略。
 * 比如使用 RouteSelector 和 RouteDatabase 在建联失败后的多 IP 路由的选择；
 * HttpStream 流的创建；
 * Connection 的创建和使用 ConnectionPool 进行连接复用等
 * <p>
 * This class coordinates the relationship between three entities:
 * <p>
 * <ul>
 * <li><strong>Connections:</strong> physical socket connections to remote servers. These are
 * potentially slow to establish so it is necessary to be able to cancel a connection
 * currently being connected.
 * <br>
 *     Connections: 和远程服务的物理 socket 连接。可能创建连接很慢，所以要能取消当前的连接。
 * <li><strong>Streams:</strong> logical HTTP request/response pairs that are layered on
 * connections. Each connection has its own allocation limit, which defines how many
 * concurrent streams that connection can carry. HTTP/1.x connections can carry 1 stream
 * at a time, HTTP/2 typically carry multiple.
 * <br>
 *     Streams: 处于连接层中的 HTTP 请求/相应对。每个连接有自己的分配限制（一个连接同时可以有多少个 streams），
 *     HTTP/1.x 协议上可以有1个，HTTP/2 协议一般可以有多个。
 * <li><strong>Calls:</strong> a logical sequence of streams, typically an initial request and
 * its follow up requests. We prefer to keep all streams of a single call on the same
 * connection for better behavior and locality.
 * <br>
 *     Calls: 一个初始的请求和它接连的请求的一系列 streams。为了更好的性能，我们倾向于保持一个单独请求的所有 streams 在同一个连接中
 * </ul>
 * <p>
 * <p>Instances of this class act on behalf of the call, using one or more streams over one or more
 * connections. This class has APIs to release each of the above resources:
 * <br>
 *     此类的实例，能够实现连接复用。提供如下 APIs 来释放上述资源。
 * <p>
 * <ul>
 * <li>{@link #noNewStreams()} prevents the connection from being used for new streams in the
 * future. Use this after a {@code Connection: close} header, or when the connection may be
 * inconsistent.
 * <br>
 *     防止连接被新的 streams 使用。在 Connection 关闭 header，或者不正常时下调用。
 *
 *
 * <li>{@link #streamFinished streamFinished()} releases the active stream from this allocation.
 * Note that only one stream may be active at a given time, so it is necessary to call
 * <br>
 *
 * {@link #streamFinished streamFinished()} before creating a subsequent stream with {@link
 * #newStream newStream()}.
 * <li>{@link #release()} removes the call's hold on the connection. Note that this won't
 * immediately free the connection if there is a stream still lingering. That happens when a
 * call is complete but its response body has yet to be fully consumed.
 * </ul>
 * <p>
 * <p>This class supports {@linkplain #cancel asynchronous canceling}. This is intended to have the
 * smallest blast radius possible. If an HTTP/2 stream is active, canceling will cancel that stream
 * but not the other streams sharing its connection. But if the TLS handshake is still in progress
 * then canceling may break the entire connection.
 */
public final class StreamAllocation {
    public final Address address;
    private RouteSelector.Selection routeSelection;
    private Route route;
    private final ConnectionPool connectionPool;
    public final Call call;
    public final EventListener eventListener;
    private final Object callStackTrace;

    // State guarded by connectionPool.
    private final RouteSelector routeSelector;
    private int refusedStreamCount;
    private RealConnection connection;
    private boolean released;
    private boolean canceled;
    private HttpCodec codec;

    public StreamAllocation(ConnectionPool connectionPool, Address address, Call call,
                            EventListener eventListener, Object callStackTrace) {
        this.connectionPool = connectionPool;
        this.address = address;
        this.call = call;
        this.eventListener = eventListener;
        this.routeSelector = new RouteSelector(address, routeDatabase(), call, eventListener);
        this.callStackTrace = callStackTrace;
    }

    public HttpCodec newStream(
            OkHttpClient client, Interceptor.Chain chain, boolean doExtensiveHealthChecks) {
        int connectTimeout = chain.connectTimeoutMillis();
        int readTimeout = chain.readTimeoutMillis();
        int writeTimeout = chain.writeTimeoutMillis();
        boolean connectionRetryEnabled = client.retryOnConnectionFailure();

        try {
            RealConnection resultConnection = findHealthyConnection(connectTimeout, readTimeout,
                    writeTimeout, connectionRetryEnabled, doExtensiveHealthChecks);
            HttpCodec resultCodec = resultConnection.newCodec(client, chain, this);

            synchronized (connectionPool) {
                codec = resultCodec;
                return resultCodec;
            }
        } catch (IOException e) {
            throw new RouteException(e);
        }
    }

    /**
     * Finds a connection and returns it if it is healthy. If it is unhealthy the process is repeated
     * until a healthy connection is found.
     */
    private RealConnection findHealthyConnection(int connectTimeout, int readTimeout,
                                                 int writeTimeout, boolean connectionRetryEnabled, boolean doExtensiveHealthChecks)
            throws IOException {
        while (true) {
            RealConnection candidate = findConnection(connectTimeout, readTimeout, writeTimeout,
                    connectionRetryEnabled);

            // If this is a brand new connection, we can skip the extensive health checks.
            // 如果是个全新的连接，可以跳过进一步检查
            synchronized (connectionPool) {
                if (candidate.successCount == 0) {
                    return candidate;
                }
            }

            // Do a (potentially slow) check to confirm that the pooled connection is still good. If it
            // isn't, take it out of the pool and start again.
            // 检查连接池中的连接是否良好，如果不好，从池中取出，并重连
            if (!candidate.isHealthy(doExtensiveHealthChecks)) {
                noNewStreams();
                continue;
            }

            return candidate;
        }
    }

    /**
     * Returns a connection to host a new stream. This prefers the existing connection if it exists,
     * then the pool, finally building a new connection.
     */
    private RealConnection findConnection(int connectTimeout, int readTimeout, int writeTimeout,
                                          boolean connectionRetryEnabled) throws IOException {
        boolean foundPooledConnection = false;
        RealConnection result = null;
        Route selectedRoute = null;
        synchronized (connectionPool) {
            if (released) throw new IllegalStateException("released");
            if (codec != null) throw new IllegalStateException("codec != null");
            if (canceled) throw new IOException("Canceled");

            // Attempt to use an already-allocated connection.
            // 尝试使用已经分配的连接
            RealConnection allocatedConnection = this.connection;
            if (allocatedConnection != null && !allocatedConnection.noNewStreams) {
                return allocatedConnection;
            }

            // Attempt to get a connection from the pool.
            // 尝试从连接池中获取
            // Internal.instance 在 OkHttpClient 中实例化的 --> ConnectionPool.get --> this.acquire
            Internal.instance.get(connectionPool, address, this, null);
            if (connection != null) {
                foundPooledConnection = true;
                result = connection;
            } else {
                selectedRoute = route;
            }
        }

        // If we found a pooled connection, we're done.
        if (foundPooledConnection) {
            eventListener.connectionAcquired(call, result);
            return result;
        }

        // If we need a route selection, make one. This is a blocking operation.
        boolean newRouteSelection = false;
        if (selectedRoute == null && (routeSelection == null || !routeSelection.hasNext())) {
            newRouteSelection = true;
            routeSelection = routeSelector.next();
        }

        synchronized (connectionPool) {
            if (canceled) throw new IOException("Canceled");

            if (newRouteSelection) {
                // Now that we have a set of IP addresses, make another attempt at getting a connection from
                // the pool. This could match due to connection coalescing.
                List<Route> routes = routeSelection.getAll();
                for (int i = 0, size = routes.size(); i < size; i++) {
                    Route route = routes.get(i);
                    Internal.instance.get(connectionPool, address, this, route);
                    if (connection != null) {
                        foundPooledConnection = true;
                        result = connection;
                        this.route = route;
                        break;
                    }
                }
            }

            if (!foundPooledConnection) {
                if (selectedRoute == null) {
                    selectedRoute = routeSelection.next();
                }

                // Create a connection and assign it to this allocation immediately. This makes it possible
                // for an asynchronous cancel() to interrupt the handshake we're about to do.
                route = selectedRoute;
                refusedStreamCount = 0;
                result = new RealConnection(connectionPool, selectedRoute);
                acquire(result);
            }
        }

        // We have a connection. Either a connected one from the pool, or one we need to connect.
        eventListener.connectionAcquired(call, result);

        // If we found a pooled connection on the 2nd time around, we're done.
        if (foundPooledConnection) {
            return result;
        }

        // Do TCP + TLS handshakes. This is a blocking operation.
        result.connect(
                connectTimeout, readTimeout, writeTimeout, connectionRetryEnabled, call, eventListener);
        routeDatabase().connected(result.route());

        Socket socket = null;
        synchronized (connectionPool) {
            // Pool the connection.
            Internal.instance.put(connectionPool, result);

            // If another multiplexed connection to the same address was created concurrently, then
            // release this connection and acquire that one.
            if (result.isMultiplexed()) {
                socket = Internal.instance.deduplicate(connectionPool, address, this);
                result = connection;
            }
        }
        closeQuietly(socket);

        return result;
    }

    public void streamFinished(boolean noNewStreams, HttpCodec codec) {
        Socket socket;
        Connection releasedConnection;
        synchronized (connectionPool) {
            if (codec == null || codec != this.codec) {
                throw new IllegalStateException("expected " + this.codec + " but was " + codec);
            }
            if (!noNewStreams) {
                connection.successCount++;
            }
            releasedConnection = connection;
            socket = deallocate(noNewStreams, false, true);
            if (connection != null) releasedConnection = null;
        }
        closeQuietly(socket);
        if (releasedConnection != null) {
            eventListener.connectionReleased(call, releasedConnection);
        }
    }

    public HttpCodec codec() {
        synchronized (connectionPool) {
            return codec;
        }
    }

    private RouteDatabase routeDatabase() {
        return Internal.instance.routeDatabase(connectionPool);
    }

    public synchronized RealConnection connection() {
        return connection;
    }

    public void release() {
        Socket socket;
        Connection releasedConnection;
        synchronized (connectionPool) {
            releasedConnection = connection;
            socket = deallocate(false, true, false);
            if (connection != null) releasedConnection = null;
        }
        closeQuietly(socket);
        if (releasedConnection != null) {
            eventListener.connectionReleased(call, releasedConnection);
        }
    }

    /**
     * Forbid new streams from being created on the connection that hosts this allocation.
     * <br>
     *     禁止 host 在此的连接创建新的 stream
     */
    public void noNewStreams() {
        Socket socket;
        Connection releasedConnection;
        synchronized (connectionPool) {
            releasedConnection = connection;
            socket = deallocate(true, false, false);
            if (connection != null) releasedConnection = null;
        }
        closeQuietly(socket);
        if (releasedConnection != null) {
            eventListener.connectionReleased(call, releasedConnection);
        }
    }

    /**
     * Releases resources held by this allocation. If sufficient resources are allocated, the
     * connection will be detached or closed. Callers must be synchronized on the connection pool.
     * <p>
     * <p>Returns a closeable that the caller should pass to {@link Util#closeQuietly} upon completion
     * of the synchronized block. (We don't do I/O while synchronized on the connection pool.)
     */
    private Socket deallocate(boolean noNewStreams, boolean released, boolean streamFinished) {
        assert (Thread.holdsLock(connectionPool));

        if (streamFinished) {
            this.codec = null;
        }
        if (released) {
            this.released = true;
        }
        Socket socket = null;
        if (connection != null) {
            if (noNewStreams) {
                connection.noNewStreams = true;
            }
            if (this.codec == null && (this.released || connection.noNewStreams)) {
                release(connection);
                if (connection.allocations.isEmpty()) {
                    connection.idleAtNanos = System.nanoTime();
                    if (Internal.instance.connectionBecameIdle(connectionPool, connection)) {
                        socket = connection.socket();
                    }
                }
                connection = null;
            }
        }
        return socket;
    }

    public void cancel() {
        HttpCodec codecToCancel;
        RealConnection connectionToCancel;
        synchronized (connectionPool) {
            canceled = true;
            codecToCancel = codec;
            connectionToCancel = connection;
        }
        if (codecToCancel != null) {
            codecToCancel.cancel();
        } else if (connectionToCancel != null) {
            connectionToCancel.cancel();
        }
    }

    public void streamFailed(IOException e) {
        Socket socket;
        Connection releasedConnection;
        boolean noNewStreams = false;

        synchronized (connectionPool) {
            if (e instanceof StreamResetException) {
                StreamResetException streamResetException = (StreamResetException) e;
                if (streamResetException.errorCode == ErrorCode.REFUSED_STREAM) {
                    refusedStreamCount++;
                }
                // On HTTP/2 stream errors, retry REFUSED_STREAM errors once on the same connection. All
                // other errors must be retried on a new connection.
                if (streamResetException.errorCode != ErrorCode.REFUSED_STREAM || refusedStreamCount > 1) {
                    noNewStreams = true;
                    route = null;
                }
            } else if (connection != null
                    && (!connection.isMultiplexed() || e instanceof ConnectionShutdownException)) {
                noNewStreams = true;

                // If this route hasn't completed a call, avoid it for new connections.
                if (connection.successCount == 0) {
                    if (route != null && e != null) {
                        routeSelector.connectFailed(route, e);
                    }
                    route = null;
                }
            }
            releasedConnection = connection;
            socket = deallocate(noNewStreams, false, true);
            if (connection != null) releasedConnection = null;
        }

        closeQuietly(socket);
        if (releasedConnection != null) {
            eventListener.connectionReleased(call, releasedConnection);
        }
    }

    /**
     * Use this allocation to hold {@code connection}. Each call to this must be paired with a call to
     * {@link #release} on the same connection.
     * <br>
     *     让此 allocation 持有连接。同一个连接，此方法的调用要和 release 方法成对出现。
     */
    public void acquire(RealConnection connection) {
        assert (Thread.holdsLock(connectionPool));
        if (this.connection != null) throw new IllegalStateException();

        this.connection = connection;
        connection.allocations.add(new StreamAllocationReference(this, callStackTrace));
    }

    /**
     * Remove this allocation from the connection's list of allocations.
     */
    private void release(RealConnection connection) {
        for (int i = 0, size = connection.allocations.size(); i < size; i++) {
            Reference<StreamAllocation> reference = connection.allocations.get(i);
            if (reference.get() == this) {
                connection.allocations.remove(i);
                return;
            }
        }
        throw new IllegalStateException();
    }

    /**
     * Release the connection held by this connection and acquire {@code newConnection} instead. It is
     * only safe to call this if the held connection is newly connected but duplicated by {@code
     * newConnection}. Typically this occurs when concurrently connecting to an HTTP/2 webserver.
     * <p>
     * <p>Returns a closeable that the caller should pass to {@link Util#closeQuietly} upon completion
     * of the synchronized block. (We don't do I/O while synchronized on the connection pool.)
     */
    public Socket releaseAndAcquire(RealConnection newConnection) {
        assert (Thread.holdsLock(connectionPool));
        if (codec != null || connection.allocations.size() != 1) throw new IllegalStateException();

        // Release the old connection.
        Reference<StreamAllocation> onlyAllocation = connection.allocations.get(0);
        Socket socket = deallocate(true, false, false);

        // Acquire the new connection.
        this.connection = newConnection;
        newConnection.allocations.add(onlyAllocation);

        return socket;
    }

    public boolean hasMoreRoutes() {
        return route != null
                || (routeSelection != null && routeSelection.hasNext())
                || routeSelector.hasNext();
    }

    @Override
    public String toString() {
        RealConnection connection = connection();
        return connection != null ? connection.toString() : address.toString();
    }

    public static final class StreamAllocationReference extends WeakReference<StreamAllocation> {
        /**
         * Captures the stack trace at the time the Call is executed or enqueued. This is helpful for
         * identifying the origin of connection leaks.
         */
        public final Object callStackTrace;

        StreamAllocationReference(StreamAllocation referent, Object callStackTrace) {
            super(referent);
            this.callStackTrace = callStackTrace;
        }
    }
}
