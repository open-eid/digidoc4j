package org.digidoc4j.test;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import org.hamcrest.Matcher;
import org.hamcrest.MatcherAssert;
import org.hamcrest.collection.IsIterableContainingInOrder;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class TestLog {

    private final Appender<ILoggingEvent> mockedAppender;

    public TestLog() {
        this("org.digidoc4j");
    }

    public TestLog(Class<?> loggerClass) {
        this(loggerClass.getCanonicalName());
    }

    @SuppressWarnings("unchecked")
    public TestLog(String loggerName) {
        mockedAppender = (Appender<ILoggingEvent>) Mockito.mock(Appender.class);
        Logger logger = (Logger) LoggerFactory.getLogger(loggerName);
        logger.addAppender(mockedAppender);
    }

    public void verifyLogInOrder(Matcher<?>... matchers) {
        verifyLogInOrder(logEvent -> true, matchers);
    }

    @SuppressWarnings("unchecked")
    public void verifyLogInOrder(Predicate<ILoggingEvent> logEventFilter, Matcher<?>... matchers) {
        ArgumentCaptor<ILoggingEvent> argumentCaptor = ArgumentCaptor.forClass(ILoggingEvent.class);
        Mockito.verify(mockedAppender, Mockito.atLeast(1)).doAppend(argumentCaptor.capture());
        List<String> listOfMessages = argumentCaptor.getAllValues().stream().filter(logEventFilter).map(ILoggingEvent::getFormattedMessage).collect(Collectors.toList());
        // NB: Make sure the correct overload of IsIterableContainingInOrder.contains is called, otherwise the matchers are wrapped twice and matching won't work!
        MatcherAssert.assertThat(listOfMessages, IsIterableContainingInOrder.contains((Matcher[]) matchers));
    }

    public void verifyLogEmpty() {
        Mockito.verifyNoInteractions(mockedAppender);
    }

    @SuppressWarnings("unchecked")
    public void reset() {
        Mockito.reset(mockedAppender);
    }

}
