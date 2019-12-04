package org.digidoc4j.impl;

import org.digidoc4j.ServiceType;

public class ServiceAccessEvent {

    private final String serviceUrl;

    private final ServiceType serviceType;

    private final boolean success;

    public ServiceAccessEvent(String serviceUrl, ServiceType serviceType, boolean success) {
        this.serviceUrl = serviceUrl;
        this.serviceType = serviceType;
        this.success = success;
    }

    public String getServiceUrl() {
        return serviceUrl;
    }

    public ServiceType getServiceType() {
        return serviceType;
    }

    public boolean isSuccess() {
        return success;
    }

}
