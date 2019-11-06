package org.digidoc4j.impl;

import org.digidoc4j.ServiceType;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

@RunWith(MockitoJUnitRunner.class)
public class ServiceAccessScopeTest {

    @Mock
    private ServiceAccessEvent mockedEvent;
    @Mock
    private ServiceAccessListener mockedListener;
    @Mock
    private Supplier<ServiceAccessEvent> mockedEventSupplier;

    @Before
    public void setUpMockedEventSupplier() {
        Mockito.doReturn(mockedEvent).when(mockedEventSupplier).get();
    }

    @Test
    public void listenerShouldBeNotifiedFromInsideServiceAccessScope() {
        try (ServiceAccessScope scope = new ServiceAccessScope(mockedListener)) {
            ServiceAccessScope.notifyExternalServiceAccessListenerIfPresent(mockedEventSupplier);
        }
        Mockito.verify(mockedEventSupplier, Mockito.times(1)).get();
        Mockito.verify(mockedListener, Mockito.times(1)).accept(mockedEvent);
        Mockito.verifyNoMoreInteractions(mockedEventSupplier, mockedListener);
        Mockito.verifyZeroInteractions(mockedEvent);
    }

    @Test
    public void listenerShouldNotBeNotifiedBeforeEnteringServiceAccessScope() {
        ServiceAccessScope.notifyExternalServiceAccessListenerIfPresent(mockedEventSupplier);
        try (ServiceAccessScope scope = new ServiceAccessScope(mockedListener)) {
        }
        Mockito.verifyZeroInteractions(mockedEventSupplier, mockedListener, mockedEvent);
    }

    @Test
    public void listenerShouldNotBeNotifiedAfterLeavingServiceAccessScope() {
        try (ServiceAccessScope scope = new ServiceAccessScope(mockedListener)) {
        }
        ServiceAccessScope.notifyExternalServiceAccessListenerIfPresent(mockedEventSupplier);
        Mockito.verifyZeroInteractions(mockedEventSupplier, mockedListener, mockedEvent);
    }

    @Test
    public void listenerShouldNotBeNotifiedAfterManuallyClosingServiceAccessScope() {
        try (ServiceAccessScope scope = new ServiceAccessScope(mockedListener)) {
            scope.close();
            ServiceAccessScope.notifyExternalServiceAccessListenerIfPresent(mockedEventSupplier);
        }
        Mockito.verifyZeroInteractions(mockedEventSupplier, mockedListener, mockedEvent);
    }

    @Test
    public void eventsShouldBeCaughtOnlyInTheSameThreadTheyWerePublishedIn() throws Exception {
        ThreadSafeListener threadSafeListener = new ThreadSafeListener();
        ExecutorService executorService = Executors.newFixedThreadPool(4);

        try (ServiceAccessScope scope = new ServiceAccessScope(threadSafeListener)) {
            executorService.submit(() -> notifyExternalServiceAccessListenerWithoutExplicitScope(ServiceType.AIA_OCSP));
            ServiceAccessScope.notifyExternalServiceAccessListenerIfPresent(new ThreadBasedEventSupplier(ServiceType.TSP));
            executorService.submit(() -> notifyExternalServiceAccessListenerWithoutExplicitScope(ServiceType.AIA_OCSP));
            ServiceAccessScope.notifyExternalServiceAccessListenerIfPresent(new ThreadBasedEventSupplier(ServiceType.OCSP));
            executorService.submit(() -> notifyExternalServiceAccessListenerWithoutExplicitScope(ServiceType.AIA_OCSP));

            Future<ThreadSafeListener> result = executorService.submit(() -> notifyExternalServiceAccessListenerInLocalScope(ServiceType.AIA_OCSP));
            Assert.assertEquals(1, result.get().getReceivedEvents().size());
        } finally {
            executorService.shutdown();
            Assert.assertTrue(
                    "Abnormal termination of " + executorService.getClass().getSimpleName(),
                    executorService.awaitTermination(10L, TimeUnit.SECONDS)
            );
        }

        List<ServiceAccessEvent> receivedEvents = threadSafeListener.getReceivedEvents();
        Assert.assertEquals(2, receivedEvents.size());

        assertEventFromCurrentThread(ServiceType.TSP, receivedEvents.get(0));
        assertEventFromCurrentThread(ServiceType.OCSP, receivedEvents.get(1));
    }

    static void notifyExternalServiceAccessListenerWithoutExplicitScope(ServiceType serviceType) {
        ServiceAccessScope.notifyExternalServiceAccessListenerIfPresent(new ThreadBasedEventSupplier(serviceType));
    }

    static ThreadSafeListener notifyExternalServiceAccessListenerInLocalScope(ServiceType serviceType) {
        ThreadSafeListener threadSafeListener = new ThreadSafeListener();
        try (ServiceAccessScope scope = new ServiceAccessScope(threadSafeListener)) {
            notifyExternalServiceAccessListenerWithoutExplicitScope(serviceType);
        }
        List<ServiceAccessEvent> receivedEvents = threadSafeListener.getReceivedEvents();
        Assert.assertEquals(1, receivedEvents.size());
        assertEventFromCurrentThread(serviceType, receivedEvents.get(0));
        return threadSafeListener;
    }

    static void assertEventFromCurrentThread(ServiceType expectedServiceType, ServiceAccessEvent actualEvent) {
        Assert.assertEquals(Thread.currentThread().getName() + "/" + expectedServiceType, actualEvent.getServiceUrl());
        Assert.assertEquals(expectedServiceType, actualEvent.getServiceType());
    }

    static class ThreadSafeListener implements ServiceAccessListener {

        private final ArrayList<ServiceAccessEvent> receivedEvents = new ArrayList<>();

        @Override
        public synchronized void accept(ServiceAccessEvent serviceAccessEvent) {
            receivedEvents.add(serviceAccessEvent);
        }

        public synchronized List<ServiceAccessEvent> getReceivedEvents() {
            return new ArrayList<>(receivedEvents);
        }

    }

    static class ThreadBasedEventSupplier implements Supplier<ServiceAccessEvent> {

        private final ServiceType serviceType;

        public ThreadBasedEventSupplier(ServiceType serviceType) {
            this.serviceType = serviceType;
        }

        @Override
        public ServiceAccessEvent get() {
            String serviceUrl = Thread.currentThread().getName() + "/" + serviceType;
            return new ServiceAccessEvent(serviceUrl, serviceType);
        }

    }

}