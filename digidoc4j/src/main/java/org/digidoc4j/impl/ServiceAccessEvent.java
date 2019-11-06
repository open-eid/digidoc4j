package org.digidoc4j.impl;

import org.digidoc4j.ServiceType;

public class ServiceAccessEvent {

    private final String serviceUrl;

    private final ServiceType serviceType;

    public ServiceAccessEvent(String serviceUrl, ServiceType serviceType) {
        this.serviceUrl = serviceUrl;
        this.serviceType = serviceType;
    }

    public String getServiceUrl() {
        return serviceUrl;
    }

    public ServiceType getServiceType() {
        return serviceType;
    }

}
