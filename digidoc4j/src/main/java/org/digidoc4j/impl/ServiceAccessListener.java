package org.digidoc4j.impl;

import java.util.function.Consumer;

@FunctionalInterface
public interface ServiceAccessListener extends Consumer<ServiceAccessEvent> {
}
