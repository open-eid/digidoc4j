package org.digidoc4j.impl;

import java.util.function.Supplier;

/**
 * A mechanism for managing the scope of an active {@link ServiceAccessListener} in the context of the current
 * thread of execution.
 *
 * Example usage:
 * <pre>{@code
 * ServiceAccessListener listener = e -> // handle the event;
 *
 * try (ServiceAccessScope scope = new ServiceAccessScope(listener)) {
 *     // serially executed code that may potentially notify the listener
 * }
 * }</pre>
 */
public final class ServiceAccessScope implements AutoCloseable {

    /**
     * {@link ThreadLocal} that keeps track on the currently scoped {@link ServiceAccessListener}.
     */
    private static final ThreadLocal<ServiceAccessListener> listenerThreadLocal = new ThreadLocal<>();

    /**
     * Invokes {@link ServiceAccessListener#accept(Object)} with an instance of {@link ServiceAccessEvent} provided by
     * {@code eventSupplier}, if there is a {@link ServiceAccessListener} present in the current scope.
     *
     * @param eventSupplier supplier that returns appropriate {@link ServiceAccessEvent} if required
     */
    static void notifyExternalServiceAccessListenerIfPresent(Supplier<ServiceAccessEvent> eventSupplier) {
        ServiceAccessListener eventListener = listenerThreadLocal.get();
        if (eventListener != null) {
            eventListener.accept(eventSupplier.get());
        }
    }

    /**
     * Creates an instance of {@code ServiceAccessScope} with the specified {@link ServiceAccessListener} that will
     * be active in this scope.
     * Should be used inside the {@code try}-with-resources statement!
     *
     * @param eventListener an instance of {@link ServiceAccessListener} that will be managed by this scope
     */
    public ServiceAccessScope(ServiceAccessListener eventListener) {
        listenerThreadLocal.set(eventListener);
    }

    /**
     * Ends(/closes) this scope.
     * Is invoked automatically if managed by the {@code try}-with-resources statement, otherwise <strong>must</strong>
     * be invoked explicitly either in the finally block or by some other reliable means to prevent the managed
     * {@link ServiceAccessListener} from leaking out from its intended scope!
     * Failure to end(/close) this scope properly may cause unexpected behaviour and/or prevent the managed
     * {@link ServiceAccessListener} from being garbage collected!
     */
    @Override
    public void close() {
        listenerThreadLocal.remove();
    }

}
