/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.tsl;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.tsl.DownloadInfoRecord;
import eu.europa.esig.dss.model.tsl.LOTLInfo;
import eu.europa.esig.dss.model.tsl.ParsingInfoRecord;
import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.model.tsl.ValidationInfoRecord;
import eu.europa.esig.dss.tsl.cache.state.CacheStateEnum;
import eu.europa.esig.dss.tsl.dto.AbstractCacheDTO;
import eu.europa.esig.dss.tsl.dto.DownloadCacheDTO;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.dto.ValidationCacheDTO;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.TslDownloadException;
import org.digidoc4j.exceptions.TslParsingException;
import org.digidoc4j.exceptions.TslRefreshException;
import org.digidoc4j.exceptions.TslValidationException;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RunWith(MockitoJUnitRunner.class)
public class DefaultTSLRefreshCallbackTest extends AbstractTest {

  private static final String LOTL_URL_1 = "http://lotl.host.first";

  private static final String TL_URL_1 = "http://tl.host.first";
  private static final String TL_URL_2 = "http://tl.host.second";
  private static final String TL_URL_3 = "http://tl.host.third";
  private static final String TL_URL_4 = "http://tl.host.fourth";

  private static final String TERRITORY_1 = "T1";
  private static final String TERRITORY_2 = "T2";
  private static final String TERRITORY_3 = "T3";
  private static final String TERRITORY_4 = "T4";

  @Mock
  private Configuration configuration;
  @InjectMocks
  private DefaultTSLRefreshCallback tslRefreshCallback;

  @Test
  public void testSummaryWithNullLOTLInfos() {
    testSummaryWithNoLOTLInfos(null);
  }

  @Test
  public void testSummaryWithEmptyLOTLInfos() {
    testSummaryWithNoLOTLInfos(Collections.emptyList());
  }

  private void testSummaryWithNoLOTLInfos(List<LOTLInfo> lotlInfos) {
    TLValidationJobSummary summary = Mockito.mock(TLValidationJobSummary.class);
    Mockito.doReturn(lotlInfos).when(summary).getLOTLInfos();

    TslRefreshException caughtException = Assert.assertThrows(
            TslRefreshException.class,
            () -> tslRefreshCallback.ensureTSLState(summary)
    );

    Assert.assertEquals("No TSL refresh info found!", caughtException.getMessage());
    Mockito.verify(summary).getLOTLInfos();
    Mockito.verifyNoMoreInteractions(summary);
    Mockito.verifyNoInteractions(configuration);
  }

  @Test
  public void testSingleLOTLInfoWithNoDownloadInfo() {
    TslDownloadException caughtException = testSingleLOTLInfoThrowingDownloadException(null);
    Assert.assertEquals(
            String.format("No download info found for <%s> LoTL: %s", TERRITORY_1, LOTL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithDownloadError() {
    TslDownloadException caughtException = testSingleLOTLInfoThrowingDownloadException(
            withErrorState(new DownloadCacheDTO(), "Exception message")
    );
    Assert.assertEquals(
            String.format("Failed to download <%s> LoTL: %s", TERRITORY_1, LOTL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNotNull(caughtException.getCause());
    Assert.assertTrue(caughtException.getCause() instanceof TslDownloadException);
    Assert.assertEquals("Exception message", caughtException.getCause().getMessage());
  }

  @Test
  public void testSingleLOTLInfoWithDownloadRefreshNeeded() {
    TslDownloadException caughtException = testSingleLOTLInfoThrowingDownloadException(
            withState(new DownloadCacheDTO(), CacheStateEnum.REFRESH_NEEDED)
    );
    Assert.assertEquals(
            String.format("(Re)download needed for <%s> LoTL: %s", TERRITORY_1, LOTL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithUnexpectedDownloadStatus() {
    for (CacheStateEnum cacheState : unexpectedCacheStates()) {
      TslDownloadException caughtException = testSingleLOTLInfoThrowingDownloadException(
              withState(new DownloadCacheDTO(), cacheState)
      );
      Assert.assertEquals(
              String.format("Unexpected download status '%s' for <%s> LoTL: %s", cacheState, TERRITORY_1, LOTL_URL_1),
              caughtException.getMessage()
      );
      Assert.assertNull(caughtException.getCause());
      Mockito.reset(configuration);
    }
  }

  private TslDownloadException testSingleLOTLInfoThrowingDownloadException(DownloadInfoRecord downloadInfo) {
    LOTLInfo lotlInfo = new LOTLInfo(
            downloadInfo,
            withSynchronizedState(new ParsingCacheDTO(), TERRITORY_1),
            withSynchronizedState(new ValidationCacheDTO(), Indication.TOTAL_PASSED),
            LOTL_URL_1
    );

    TslDownloadException caughtException = testSingleLOTLInfoThrowingException(lotlInfo, TslDownloadException.class);

    Assert.assertArrayEquals(new Throwable[0], caughtException.getSuppressed());
    Mockito.verifyNoInteractions(configuration);
    return caughtException;
  }

  @Test
  public void testSingleLOTLInfoWithNoParsingInfo() {
    TslParsingException caughtException = testSingleLOTLInfoThrowingParsingException(null);
    Assert.assertEquals(
            String.format("No parsing info found for LoTL: %s", LOTL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithParsingError() {
    TslParsingException caughtException = testSingleLOTLInfoThrowingParsingException(
            withErrorState(new ParsingCacheDTO(), "Exception message")
    );
    Assert.assertEquals(
            String.format("Failed to parse LoTL: %s", LOTL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNotNull(caughtException.getCause());
    Assert.assertTrue(caughtException.getCause() instanceof TslParsingException);
    Assert.assertEquals("Exception message", caughtException.getCause().getMessage());
  }

  @Test
  public void testSingleLOTLInfoWithParsingRefreshNeeded() {
    TslParsingException caughtException = testSingleLOTLInfoThrowingParsingException(
            withState(new ParsingCacheDTO(), CacheStateEnum.REFRESH_NEEDED)
    );
    Assert.assertEquals(
            String.format("(Re)parsing needed for LoTL: %s", LOTL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithUnexpectedParsingStatus() {
    for (CacheStateEnum cacheState : unexpectedCacheStates()) {
      TslParsingException caughtException = testSingleLOTLInfoThrowingParsingException(
              withState(new ParsingCacheDTO(), cacheState)
      );
      Assert.assertEquals(
              String.format("Unexpected parsing status '%s' for LoTL: %s", cacheState, LOTL_URL_1),
              caughtException.getMessage()
      );
      Assert.assertNull(caughtException.getCause());
      Mockito.reset(configuration);
    }
  }

  private TslParsingException testSingleLOTLInfoThrowingParsingException(ParsingInfoRecord parsingInfo) {
    LOTLInfo lotlInfo = new LOTLInfo(
            withState(new DownloadCacheDTO(), CacheStateEnum.SYNCHRONIZED),
            parsingInfo,
            withSynchronizedState(new ValidationCacheDTO(), Indication.TOTAL_PASSED),
            LOTL_URL_1
    );

    TslParsingException caughtException = testSingleLOTLInfoThrowingException(lotlInfo, TslParsingException.class);

    Assert.assertArrayEquals(new Throwable[0], caughtException.getSuppressed());
    Mockito.verifyNoInteractions(configuration);
    return caughtException;
  }

  @Test
  public void testSingleLOTLInfoWithNoValidationInfo() {
    TslValidationException caughtException = testSingleLOTLInfoThrowingValidationException(null);
    Assert.assertEquals(
            String.format("No validation info found for <%s> LoTL: %s", TERRITORY_1, LOTL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithValidationError() {
    TslValidationException caughtException = testSingleLOTLInfoThrowingValidationException(
            withErrorState(new ValidationCacheDTO(), "Exception message")
    );
    Assert.assertEquals(
            String.format("Failed to validate <%s> LoTL: %s", TERRITORY_1, LOTL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNotNull(caughtException.getCause());
    Assert.assertTrue(caughtException.getCause() instanceof TslValidationException);
    Assert.assertEquals("Exception message", caughtException.getCause().getMessage());
  }

  @Test
  public void testSingleLOTLInfoWithValidationNotTotalPassed() {
    for (Indication indication : nonValidIndications()) {
      TslValidationException caughtException = testSingleLOTLInfoThrowingValidationException(
              withSynchronizedState(new ValidationCacheDTO(), indication)
      );
      Assert.assertEquals(
              String.format("Failed to validate <%s> LoTL: %s", TERRITORY_1, LOTL_URL_1),
              caughtException.getMessage()
      );
      Assert.assertNotNull(caughtException.getCause());
      Assert.assertTrue(caughtException.getCause() instanceof TslValidationException);
      Assert.assertEquals(
              String.format("<%s> LoTL validation failed; indication: %s", TERRITORY_1, indication),
              caughtException.getCause().getMessage()
      );
      Mockito.reset(configuration);
    }
  }

  @Test
  public void testSingleLOTLInfoWithValidationRefreshNeeded() {
    TslValidationException caughtException = testSingleLOTLInfoThrowingValidationException(
            withState(new ValidationCacheDTO(), CacheStateEnum.REFRESH_NEEDED)
    );
    Assert.assertEquals(
            String.format("(Re)validation needed for <%s> LoTL: %s", TERRITORY_1, LOTL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithUnexpectedValidationStatus() {
    for (CacheStateEnum cacheState : unexpectedCacheStates()) {
      TslValidationException caughtException = testSingleLOTLInfoThrowingValidationException(
              withState(new ValidationCacheDTO(), cacheState)
      );
      Assert.assertEquals(
              String.format("Unexpected validation status '%s' for <%s> LoTL: %s", cacheState, TERRITORY_1, LOTL_URL_1),
              caughtException.getMessage()
      );
      Assert.assertNull(caughtException.getCause());
      Mockito.reset(configuration);
    }
  }

  private TslValidationException testSingleLOTLInfoThrowingValidationException(ValidationInfoRecord validationInfo) {
    LOTLInfo lotlInfo = new LOTLInfo(
            withState(new DownloadCacheDTO(), CacheStateEnum.SYNCHRONIZED),
            withSynchronizedState(new ParsingCacheDTO(), TERRITORY_1),
            validationInfo,
            LOTL_URL_1
    );

    TslValidationException caughtException = testSingleLOTLInfoThrowingException(lotlInfo, TslValidationException.class);

    Assert.assertArrayEquals(new Throwable[0], caughtException.getSuppressed());
    Mockito.verifyNoInteractions(configuration);
    return caughtException;
  }

  @Test
  public void testSingleLOTLInfoWithDownloadErrorAndParsingRefreshNeededAndValidationRefreshNeeded() {
    LOTLInfo lotlInfo = new LOTLInfo(
            withErrorState(new DownloadCacheDTO(), "Exception message"),
            withState(new ParsingCacheDTO(), CacheStateEnum.REFRESH_NEEDED),
            withState(new ValidationCacheDTO(), CacheStateEnum.REFRESH_NEEDED),
            LOTL_URL_1
    );

    TslDownloadException caughtException = testSingleLOTLInfoThrowingException(lotlInfo, TslDownloadException.class);

    Assert.assertEquals(
            String.format("Failed to download LoTL: %s", LOTL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNotNull(caughtException.getCause());
    Assert.assertTrue(caughtException.getCause() instanceof TslDownloadException);
    Assert.assertEquals("Exception message", caughtException.getCause().getMessage());
    Assert.assertNotNull(caughtException.getSuppressed());
    Assert.assertEquals(2, caughtException.getSuppressed().length);
    Assert.assertTrue(caughtException.getSuppressed()[0] instanceof TslParsingException);
    Assert.assertEquals(
            String.format("(Re)parsing needed for LoTL: %s", LOTL_URL_1),
            caughtException.getSuppressed()[0].getMessage()
    );
    Assert.assertTrue(caughtException.getSuppressed()[1] instanceof TslValidationException);
    Assert.assertEquals(
            String.format("(Re)validation needed for LoTL: %s", LOTL_URL_1),
            caughtException.getSuppressed()[1].getMessage()
    );
    Mockito.verifyNoInteractions(configuration);
  }

  @Test
  public void testSingleLOTLInfoWithParsingErrorAndValidationRefreshNeeded() {
    LOTLInfo lotlInfo = new LOTLInfo(
            withState(new DownloadCacheDTO(), CacheStateEnum.SYNCHRONIZED),
            withErrorState(new ParsingCacheDTO(), "Exception message"),
            withState(new ValidationCacheDTO(), CacheStateEnum.REFRESH_NEEDED),
            LOTL_URL_1
    );

    TslParsingException caughtException = testSingleLOTLInfoThrowingException(lotlInfo, TslParsingException.class);

    Assert.assertEquals(
            String.format("Failed to parse LoTL: %s", LOTL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNotNull(caughtException.getCause());
    Assert.assertTrue(caughtException.getCause() instanceof TslParsingException);
    Assert.assertEquals("Exception message", caughtException.getCause().getMessage());
    Assert.assertNotNull(caughtException.getSuppressed());
    Assert.assertEquals(1, caughtException.getSuppressed().length);
    Assert.assertTrue(caughtException.getSuppressed()[0] instanceof TslValidationException);
    Assert.assertEquals(
            String.format("(Re)validation needed for LoTL: %s", LOTL_URL_1),
            caughtException.getSuppressed()[0].getMessage()
    );
    Mockito.verifyNoInteractions(configuration);
  }

  private <E extends TslRefreshException> E testSingleLOTLInfoThrowingException(LOTLInfo lotlInfo, Class<E> exceptionType) {
    TLValidationJobSummary summary = new TLValidationJobSummary(Collections.singletonList(lotlInfo), null);
    return Assert.assertThrows(exceptionType, () -> tslRefreshCallback.ensureTSLState(summary));
  }

  @Test
  public void testSingleLOTLInfoWithSingleTLInfoWithNoDownloadInfo() {
    TslDownloadException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingDownloadException(null);
    Assert.assertEquals(
            String.format("No download info found for <%s> TL: %s", TERRITORY_2, TL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithSingleTLInfoWithDownloadError() {
    TslDownloadException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingDownloadException(
            withErrorState(new DownloadCacheDTO(), "Exception message")
    );
    Assert.assertEquals(
            String.format("Failed to download <%s> TL: %s", TERRITORY_2, TL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNotNull(caughtException.getCause());
    Assert.assertTrue(caughtException.getCause() instanceof TslDownloadException);
    Assert.assertEquals("Exception message", caughtException.getCause().getMessage());
  }

  @Test
  public void testSingleLOTLInfoWithSingleTLInfoWithDownloadRefreshNeeded() {
    TslDownloadException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingDownloadException(
            withState(new DownloadCacheDTO(), CacheStateEnum.REFRESH_NEEDED)
    );
    Assert.assertEquals(
            String.format("(Re)download needed for <%s> TL: %s", TERRITORY_2, TL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithSingleTLInfoWithUnexpectedDownloadStatus() {
    for (CacheStateEnum cacheState : unexpectedCacheStates()) {
      TslDownloadException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingDownloadException(
              withState(new DownloadCacheDTO(), cacheState)
      );
      Assert.assertEquals(
              String.format("Unexpected download status '%s' for <%s> TL: %s", cacheState, TERRITORY_2, TL_URL_1),
              caughtException.getMessage()
      );
      Assert.assertNull(caughtException.getCause());
      Mockito.reset(configuration);
    }
  }

  private TslDownloadException testSingleLOTLInfoWithSingleTLInfoThrowingDownloadException(DownloadInfoRecord downloadInfo) {
    TLInfo tlInfo = new TLInfo(
            downloadInfo,
            withSynchronizedState(new ParsingCacheDTO(), TERRITORY_2),
            withSynchronizedState(new ValidationCacheDTO(), Indication.TOTAL_PASSED),
            TL_URL_1
    );

    TslRefreshException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingException(tlInfo);

    Assert.assertNotNull(caughtException.getCause());
    Assert.assertTrue(caughtException.getCause() instanceof TslDownloadException);
    Assert.assertArrayEquals(new Throwable[0], caughtException.getSuppressed());
    Mockito.verifyNoInteractions(configuration);

    TslDownloadException downloadException = (TslDownloadException) caughtException.getCause();
    Assert.assertArrayEquals(new Throwable[0], downloadException.getSuppressed());
    return downloadException;
  }

  @Test
  public void testSingleLOTLInfoWithSingleTLInfoWithNoParsingInfo() {
    TslParsingException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingParsingException(null);
    Assert.assertEquals(
            String.format("No parsing info found for TL: %s", TL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithSingleTLInfoWithParsingError() {
    TslParsingException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingParsingException(
            withErrorState(new ParsingCacheDTO(), "Exception message")
    );
    Assert.assertEquals(
            String.format("Failed to parse TL: %s", TL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNotNull(caughtException.getCause());
    Assert.assertTrue(caughtException.getCause() instanceof TslParsingException);
    Assert.assertEquals("Exception message", caughtException.getCause().getMessage());
  }

  @Test
  public void testSingleLOTLInfoWithSingleTLInfoWithParsingRefreshNeeded() {
    TslParsingException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingParsingException(
            withState(new ParsingCacheDTO(), CacheStateEnum.REFRESH_NEEDED)
    );
    Assert.assertEquals(
            String.format("(Re)parsing needed for TL: %s", TL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithSingleTLInfoInfoWithUnexpectedParsingStatus() {
    for (CacheStateEnum cacheState : unexpectedCacheStates()) {
      TslParsingException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingParsingException(
              withState(new ParsingCacheDTO(), cacheState)
      );
      Assert.assertEquals(
              String.format("Unexpected parsing status '%s' for TL: %s", cacheState, TL_URL_1),
              caughtException.getMessage()
      );
      Assert.assertNull(caughtException.getCause());
      Mockito.reset(configuration);
    }
  }

  private TslParsingException testSingleLOTLInfoWithSingleTLInfoThrowingParsingException(ParsingInfoRecord parsingInfo) {
    TLInfo tlInfo = new TLInfo(
            withState(new DownloadCacheDTO(), CacheStateEnum.SYNCHRONIZED),
            parsingInfo,
            withSynchronizedState(new ValidationCacheDTO(), Indication.TOTAL_PASSED),
            TL_URL_1
    );

    TslRefreshException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingException(tlInfo);

    Assert.assertNotNull(caughtException.getCause());
    Assert.assertTrue(caughtException.getCause() instanceof TslParsingException);
    Assert.assertArrayEquals(new Throwable[0], caughtException.getSuppressed());
    Mockito.verifyNoInteractions(configuration);

    TslParsingException parsingException = (TslParsingException) caughtException.getCause();
    Assert.assertArrayEquals(new Throwable[0], parsingException.getSuppressed());
    return parsingException;
  }

  @Test
  public void testSingleLOTLInfoWithSingleTLInfoWithNoValidationInfo() {
    TslValidationException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingValidationException(null);
    Assert.assertEquals(
            String.format("No validation info found for <%s> TL: %s", TERRITORY_2, TL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithSingleTLInfoWithValidationError() {
    TslValidationException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingValidationException(
            withErrorState(new ValidationCacheDTO(), "Exception message")
    );
    Assert.assertEquals(
            String.format("Failed to validate <%s> TL: %s", TERRITORY_2, TL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNotNull(caughtException.getCause());
    Assert.assertTrue(caughtException.getCause() instanceof TslValidationException);
    Assert.assertEquals("Exception message", caughtException.getCause().getMessage());
  }

  @Test
  public void testSingleLOTLInfoWithSingleTLInfoWithValidationNotTotalPassed() {
    for (Indication indication : nonValidIndications()) {
      TslValidationException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingValidationException(
              withSynchronizedState(new ValidationCacheDTO(), indication)
      );
      Assert.assertEquals(
              String.format("Failed to validate <%s> TL: %s", TERRITORY_2, TL_URL_1),
              caughtException.getMessage()
      );
      Assert.assertNotNull(caughtException.getCause());
      Assert.assertTrue(caughtException.getCause() instanceof TslValidationException);
      Assert.assertEquals(
              String.format("<%s> TL validation failed; indication: %s", TERRITORY_2, indication),
              caughtException.getCause().getMessage()
      );
      Mockito.reset(configuration);
    }
  }

  @Test
  public void testSingleLOTLInfoWithSingleTLInfoWithValidationRefreshNeeded() {
    TslValidationException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingValidationException(
            withState(new ValidationCacheDTO(), CacheStateEnum.REFRESH_NEEDED)
    );
    Assert.assertEquals(
            String.format("(Re)validation needed for <%s> TL: %s", TERRITORY_2, TL_URL_1),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithSingleTLInfoWithUnexpectedValidationStatus() {
    for (CacheStateEnum cacheState : unexpectedCacheStates()) {
      TslValidationException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingValidationException(
              withState(new ValidationCacheDTO(), cacheState)
      );
      Assert.assertEquals(
              String.format("Unexpected validation status '%s' for <%s> TL: %s", cacheState, TERRITORY_2, TL_URL_1),
              caughtException.getMessage()
      );
      Assert.assertNull(caughtException.getCause());
      Mockito.reset(configuration);
    }
  }

  private TslValidationException testSingleLOTLInfoWithSingleTLInfoThrowingValidationException(ValidationInfoRecord validationInfo) {
    TLInfo tlInfo = new TLInfo(
            withState(new DownloadCacheDTO(), CacheStateEnum.SYNCHRONIZED),
            withSynchronizedState(new ParsingCacheDTO(), TERRITORY_2),
            validationInfo,
            TL_URL_1
    );

    TslRefreshException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingException(tlInfo);

    Assert.assertNotNull(caughtException.getCause());
    Assert.assertTrue(caughtException.getCause() instanceof TslValidationException);
    Assert.assertArrayEquals(new Throwable[0], caughtException.getSuppressed());
    Mockito.verifyNoInteractions(configuration);

    TslValidationException validationException = (TslValidationException) caughtException.getCause();
    Assert.assertArrayEquals(new Throwable[0], validationException.getSuppressed());
    return validationException;
  }

  @Test
  public void testSingleLOTLInfoWithSingleTLInfoWithDownloadErrorAndParsingRefreshNeededAndValidationRefreshNeeded() {
    TLInfo tlInfo = new TLInfo(
            withErrorState(new DownloadCacheDTO(), "Exception message"),
            withState(new ParsingCacheDTO(), CacheStateEnum.REFRESH_NEEDED),
            withState(new ValidationCacheDTO(), CacheStateEnum.REFRESH_NEEDED),
            TL_URL_1
    );

    TslRefreshException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingException(tlInfo);

    Assert.assertNull(caughtException.getCause());
    Assert.assertNotNull(caughtException.getSuppressed());
    Assert.assertEquals(3, caughtException.getSuppressed().length);

    Assert.assertTrue(caughtException.getSuppressed()[0] instanceof TslDownloadException);
    Assert.assertEquals(
            String.format("Failed to download TL: %s", TL_URL_1),
            caughtException.getSuppressed()[0].getMessage()
    );
    Assert.assertNotNull(caughtException.getSuppressed()[0].getCause());
    Assert.assertTrue(caughtException.getSuppressed()[0].getCause() instanceof TslDownloadException);
    Assert.assertEquals("Exception message", caughtException.getSuppressed()[0].getCause().getMessage());
    Assert.assertArrayEquals(new Throwable[0], caughtException.getSuppressed()[0].getSuppressed());

    Assert.assertTrue(caughtException.getSuppressed()[1] instanceof TslParsingException);
    Assert.assertEquals(
            String.format("(Re)parsing needed for TL: %s", TL_URL_1),
            caughtException.getSuppressed()[1].getMessage()
    );

    Assert.assertTrue(caughtException.getSuppressed()[2] instanceof TslValidationException);
    Assert.assertEquals(
            String.format("(Re)validation needed for TL: %s", TL_URL_1),
            caughtException.getSuppressed()[2].getMessage()
    );
    Mockito.verifyNoInteractions(configuration);
  }

  @Test
  public void testSingleLOTLInfoWithSingleTLInfoWithParsingErrorAndValidationRefreshNeeded() {
    TLInfo tlInfo = new TLInfo(
            withState(new DownloadCacheDTO(), CacheStateEnum.SYNCHRONIZED),
            withErrorState(new ParsingCacheDTO(), "Exception message"),
            withState(new ValidationCacheDTO(), CacheStateEnum.REFRESH_NEEDED),
            TL_URL_1
    );

    TslRefreshException caughtException = testSingleLOTLInfoWithSingleTLInfoThrowingException(tlInfo);

    Assert.assertNull(caughtException.getCause());
    Assert.assertNotNull(caughtException.getSuppressed());
    Assert.assertEquals(2, caughtException.getSuppressed().length);

    Assert.assertTrue(caughtException.getSuppressed()[0] instanceof TslParsingException);
    Assert.assertEquals(
            String.format("Failed to parse TL: %s", TL_URL_1),
            caughtException.getSuppressed()[0].getMessage()
    );
    Assert.assertNotNull(caughtException.getSuppressed()[0].getCause());
    Assert.assertTrue(caughtException.getSuppressed()[0].getCause() instanceof TslParsingException);
    Assert.assertEquals("Exception message", caughtException.getSuppressed()[0].getCause().getMessage());
    Assert.assertArrayEquals(new Throwable[0], caughtException.getSuppressed()[0].getSuppressed());

    Assert.assertTrue(caughtException.getSuppressed()[1] instanceof TslValidationException);
    Assert.assertEquals(
            String.format("(Re)validation needed for TL: %s", TL_URL_1),
            caughtException.getSuppressed()[1].getMessage()
    );
    Mockito.verifyNoInteractions(configuration);
  }

  private TslRefreshException testSingleLOTLInfoWithSingleTLInfoThrowingException(TLInfo tlInfo) {
    return testSingleLOTLInfoWithAllTLInfosThrowingException(Collections.singletonList(tlInfo));
  }

  @Test
  public void testSingleLOTLInfoWithMultipleTLInfosAllFail() {
    TslRefreshException caughtException = testSingleLOTLInfoWithAllTLInfosThrowingException(Arrays.asList(
            new TLInfo(
                    withErrorState(new DownloadCacheDTO(), "Exception message 1"),
                    withSynchronizedState(new ParsingCacheDTO(), TERRITORY_2),
                    withSynchronizedState(new ValidationCacheDTO(), Indication.TOTAL_PASSED),
                    TL_URL_1
            ),
            new TLInfo(
                    withState(new DownloadCacheDTO(), CacheStateEnum.SYNCHRONIZED),
                    withErrorState(new ParsingCacheDTO(), "Exception message 2"),
                    withSynchronizedState(new ValidationCacheDTO(), Indication.TOTAL_PASSED),
                    TL_URL_2
            ),
            new TLInfo(
                    withState(new DownloadCacheDTO(), CacheStateEnum.SYNCHRONIZED),
                    withSynchronizedState(new ParsingCacheDTO(), TERRITORY_3),
                    withErrorState(new ValidationCacheDTO(), "Exception message 3"),
                    TL_URL_3
            ),
            new TLInfo(
                    withState(new DownloadCacheDTO(), CacheStateEnum.SYNCHRONIZED),
                    withSynchronizedState(new ParsingCacheDTO(), TERRITORY_4),
                    withSynchronizedState(new ValidationCacheDTO(), Indication.INDETERMINATE, SubIndication.TRY_LATER),
                    TL_URL_4
            )
    ));

    Assert.assertNull(caughtException.getCause());
    Assert.assertNotNull(caughtException.getSuppressed());
    Assert.assertEquals(4, caughtException.getSuppressed().length);

    Assert.assertTrue(caughtException.getSuppressed()[0] instanceof TslDownloadException);
    Assert.assertEquals(
            String.format("Failed to download <%s> TL: %s", TERRITORY_2, TL_URL_1),
            caughtException.getSuppressed()[0].getMessage()
    );
    Assert.assertNotNull(caughtException.getSuppressed()[0].getCause());
    Assert.assertTrue(caughtException.getSuppressed()[0].getCause() instanceof TslDownloadException);
    Assert.assertEquals("Exception message 1", caughtException.getSuppressed()[0].getCause().getMessage());
    Assert.assertArrayEquals(new Throwable[0], caughtException.getSuppressed()[0].getSuppressed());

    Assert.assertTrue(caughtException.getSuppressed()[1] instanceof TslParsingException);
    Assert.assertEquals(
            String.format("Failed to parse TL: %s", TL_URL_2),
            caughtException.getSuppressed()[1].getMessage()
    );
    Assert.assertNotNull(caughtException.getSuppressed()[1].getCause());
    Assert.assertTrue(caughtException.getSuppressed()[1].getCause() instanceof TslParsingException);
    Assert.assertEquals("Exception message 2", caughtException.getSuppressed()[1].getCause().getMessage());
    Assert.assertArrayEquals(new Throwable[0], caughtException.getSuppressed()[1].getSuppressed());

    Assert.assertTrue(caughtException.getSuppressed()[2] instanceof TslValidationException);
    Assert.assertEquals(
            String.format("Failed to validate <%s> TL: %s", TERRITORY_3, TL_URL_3),
            caughtException.getSuppressed()[2].getMessage()
    );
    Assert.assertNotNull(caughtException.getSuppressed()[2].getCause());
    Assert.assertTrue(caughtException.getSuppressed()[2].getCause() instanceof TslValidationException);
    Assert.assertEquals("Exception message 3", caughtException.getSuppressed()[2].getCause().getMessage());
    Assert.assertArrayEquals(new Throwable[0], caughtException.getSuppressed()[2].getSuppressed());

    Assert.assertTrue(caughtException.getSuppressed()[3] instanceof TslValidationException);
    Assert.assertEquals(
            String.format("Failed to validate <%s> TL: %s", TERRITORY_4, TL_URL_4),
            caughtException.getSuppressed()[3].getMessage()
    );
    Assert.assertNotNull(caughtException.getSuppressed()[3].getCause());
    Assert.assertTrue(caughtException.getSuppressed()[3].getCause() instanceof TslValidationException);
    Assert.assertEquals(
            String.format("<%s> TL validation failed; indication: INDETERMINATE; sub-indication: TRY_LATER", TERRITORY_4),
            caughtException.getSuppressed()[3].getCause().getMessage()
    );
    Assert.assertArrayEquals(new Throwable[0], caughtException.getSuppressed()[3].getSuppressed());

    Mockito.verifyNoInteractions(configuration);
  }

  private TslRefreshException testSingleLOTLInfoWithAllTLInfosThrowingException(List<TLInfo> tlInfos) {
    LOTLInfo lotlInfo = createValidLOTLInfo(TERRITORY_1, LOTL_URL_1);
    lotlInfo.setTlInfos(tlInfos);

    TslRefreshException caughtException = testSingleLOTLInfoThrowingException(lotlInfo, TslRefreshException.class);

    Assert.assertEquals(
            String.format("Failed to load any trusted lists for <%s> LoTL: %s", TERRITORY_1, LOTL_URL_1),
            caughtException.getMessage()
    );
    return caughtException;
  }

  @Test
  public void testSingleLOTLInfoWithRequiredTLInfoWithNoDownloadInfo() {
    TslDownloadException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingDownloadException(null);
    Assert.assertEquals(
            String.format("No download info found for <%s> TL: %s", TERRITORY_3, TL_URL_2),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithRequiredTLInfoWithDownloadError() {
    TslDownloadException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingDownloadException(
            withErrorState(new DownloadCacheDTO(), "Exception message")
    );
    Assert.assertEquals(
            String.format("Failed to download <%s> TL: %s", TERRITORY_3, TL_URL_2),
            caughtException.getMessage()
    );
    Assert.assertNotNull(caughtException.getCause());
    Assert.assertTrue(caughtException.getCause() instanceof TslDownloadException);
    Assert.assertEquals("Exception message", caughtException.getCause().getMessage());
  }

  @Test
  public void testSingleLOTLInfoWithRequiredTLInfoWithDownloadRefreshNeeded() {
    TslDownloadException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingDownloadException(
            withState(new DownloadCacheDTO(), CacheStateEnum.REFRESH_NEEDED)
    );
    Assert.assertEquals(
            String.format("(Re)download needed for <%s> TL: %s", TERRITORY_3, TL_URL_2),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithRequiredTLInfoWithUnexpectedDownloadStatus() {
    for (CacheStateEnum cacheState : unexpectedCacheStates()) {
      TslDownloadException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingDownloadException(
              withState(new DownloadCacheDTO(), cacheState)
      );
      Assert.assertEquals(
              String.format("Unexpected download status '%s' for <%s> TL: %s", cacheState, TERRITORY_3, TL_URL_2),
              caughtException.getMessage()
      );
      Assert.assertNull(caughtException.getCause());
      Mockito.reset(configuration);
    }
  }

  private TslDownloadException testSingleLOTLInfoWithRequiredTLInfoThrowingDownloadException(DownloadInfoRecord downloadInfo) {
    TLInfo tlInfo = new TLInfo(
            downloadInfo,
            withSynchronizedState(new ParsingCacheDTO(), TERRITORY_3),
            withSynchronizedState(new ValidationCacheDTO(), Indication.TOTAL_PASSED),
            TL_URL_2
    );

    TslRefreshException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingException(tlInfo, TERRITORY_3);

    Assert.assertNotNull(caughtException.getCause());
    Assert.assertTrue(caughtException.getCause() instanceof TslDownloadException);
    Assert.assertArrayEquals(new Throwable[0], caughtException.getSuppressed());

    TslDownloadException downloadException = (TslDownloadException) caughtException.getCause();
    Assert.assertArrayEquals(new Throwable[0], downloadException.getSuppressed());
    return downloadException;
  }

  @Test
  public void testSingleLOTLInfoWithRequiredTLInfoWithNoParsingInfo() {
    TslParsingException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingParsingException(null);
    Assert.assertEquals(
            String.format("No parsing info found for TL: %s", TL_URL_2),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithRequiredTLInfoWithParsingError() {
    TslParsingException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingParsingException(
            withErrorState(new ParsingCacheDTO(), "Exception message")
    );
    Assert.assertEquals(
            String.format("Failed to parse TL: %s", TL_URL_2),
            caughtException.getMessage()
    );
    Assert.assertNotNull(caughtException.getCause());
    Assert.assertTrue(caughtException.getCause() instanceof TslParsingException);
    Assert.assertEquals("Exception message", caughtException.getCause().getMessage());
  }

  @Test
  public void testSingleLOTLInfoWithRequiredTLInfoWithParsingRefreshNeeded() {
    TslParsingException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingParsingException(
            withState(new ParsingCacheDTO(), CacheStateEnum.REFRESH_NEEDED)
    );
    Assert.assertEquals(
            String.format("(Re)parsing needed for TL: %s", TL_URL_2),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithRequiredTLInfoInfoWithUnexpectedParsingStatus() {
    for (CacheStateEnum cacheState : unexpectedCacheStates()) {
      TslParsingException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingParsingException(
              withState(new ParsingCacheDTO(), cacheState)
      );
      Assert.assertEquals(
              String.format("Unexpected parsing status '%s' for TL: %s", cacheState, TL_URL_2),
              caughtException.getMessage()
      );
      Assert.assertNull(caughtException.getCause());
      Mockito.reset(configuration);
    }
  }

  private TslParsingException testSingleLOTLInfoWithRequiredTLInfoThrowingParsingException(ParsingInfoRecord parsingInfo) {
    TLInfo tlInfo = new TLInfo(
            withState(new DownloadCacheDTO(), CacheStateEnum.SYNCHRONIZED),
            parsingInfo,
            withSynchronizedState(new ValidationCacheDTO(), Indication.TOTAL_PASSED),
            TL_URL_2
    );

    TslRefreshException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingException(tlInfo, TERRITORY_3);

    Assert.assertNotNull(caughtException.getCause());
    Assert.assertTrue(caughtException.getCause() instanceof TslParsingException);
    Assert.assertArrayEquals(new Throwable[0], caughtException.getSuppressed());

    TslParsingException parsingException = (TslParsingException) caughtException.getCause();
    Assert.assertArrayEquals(new Throwable[0], parsingException.getSuppressed());
    return parsingException;
  }

  @Test
  public void testSingleLOTLInfoWithRequiredTLInfoWithNoValidationInfo() {
    TslValidationException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingValidationException(null);
    Assert.assertEquals(
            String.format("No validation info found for <%s> TL: %s", TERRITORY_3, TL_URL_2),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithRequiredTLInfoWithValidationError() {
    TslValidationException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingValidationException(
            withErrorState(new ValidationCacheDTO(), "Exception message")
    );
    Assert.assertEquals(
            String.format("Failed to validate <%s> TL: %s", TERRITORY_3, TL_URL_2),
            caughtException.getMessage()
    );
    Assert.assertNotNull(caughtException.getCause());
    Assert.assertTrue(caughtException.getCause() instanceof TslValidationException);
    Assert.assertEquals("Exception message", caughtException.getCause().getMessage());
  }

  @Test
  public void testSingleLOTLInfoWithRequiredTLInfoWithValidationNotTotalPassed() {
    for (Indication indication : nonValidIndications()) {
      TslValidationException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingValidationException(
              withSynchronizedState(new ValidationCacheDTO(), indication)
      );
      Assert.assertEquals(
              String.format("Failed to validate <%s> TL: %s", TERRITORY_3, TL_URL_2),
              caughtException.getMessage()
      );
      Assert.assertNotNull(caughtException.getCause());
      Assert.assertTrue(caughtException.getCause() instanceof TslValidationException);
      Assert.assertEquals(
              String.format("<%s> TL validation failed; indication: %s", TERRITORY_3, indication),
              caughtException.getCause().getMessage()
      );
      Mockito.reset(configuration);
    }
  }

  @Test
  public void testSingleLOTLInfoWithRequiredTLInfoWithValidationRefreshNeeded() {
    TslValidationException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingValidationException(
            withState(new ValidationCacheDTO(), CacheStateEnum.REFRESH_NEEDED)
    );
    Assert.assertEquals(
            String.format("(Re)validation needed for <%s> TL: %s", TERRITORY_3, TL_URL_2),
            caughtException.getMessage()
    );
    Assert.assertNull(caughtException.getCause());
  }

  @Test
  public void testSingleLOTLInfoWithRequiredTLInfoWithUnexpectedValidationStatus() {
    for (CacheStateEnum cacheState : unexpectedCacheStates()) {
      TslValidationException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingValidationException(
              withState(new ValidationCacheDTO(), cacheState)
      );
      Assert.assertEquals(
              String.format("Unexpected validation status '%s' for <%s> TL: %s", cacheState, TERRITORY_3, TL_URL_2),
              caughtException.getMessage()
      );
      Assert.assertNull(caughtException.getCause());
      Mockito.reset(configuration);
    }
  }

  private TslValidationException testSingleLOTLInfoWithRequiredTLInfoThrowingValidationException(ValidationInfoRecord validationInfo) {
    TLInfo tlInfo = new TLInfo(
            withState(new DownloadCacheDTO(), CacheStateEnum.SYNCHRONIZED),
            withSynchronizedState(new ParsingCacheDTO(), TERRITORY_3),
            validationInfo,
            TL_URL_2
    );

    TslRefreshException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingException(tlInfo, TERRITORY_3);

    Assert.assertNotNull(caughtException.getCause());
    Assert.assertTrue(caughtException.getCause() instanceof TslValidationException);
    Assert.assertArrayEquals(new Throwable[0], caughtException.getSuppressed());

    TslValidationException validationException = (TslValidationException) caughtException.getCause();
    Assert.assertArrayEquals(new Throwable[0], validationException.getSuppressed());
    return validationException;
  }

  @Test
  public void testSingleLOTLInfoWithRequiredTLInfoWithDownloadErrorAndParsingRefreshNeededAndValidationRefreshNeeded() {
    TLInfo tlInfo = new TLInfo(
            withErrorState(new DownloadCacheDTO(), "Exception message"),
            withState(new ParsingCacheDTO(), CacheStateEnum.REFRESH_NEEDED),
            withState(new ValidationCacheDTO(), CacheStateEnum.REFRESH_NEEDED),
            TL_URL_1
    );

    TslRefreshException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingException(tlInfo, TERRITORY_2);

    Assert.assertNull(caughtException.getCause());
    Assert.assertNotNull(caughtException.getSuppressed());
    Assert.assertEquals(3, caughtException.getSuppressed().length);

    Assert.assertTrue(caughtException.getSuppressed()[0] instanceof TslDownloadException);
    Assert.assertEquals(
            String.format("Failed to download TL: %s", TL_URL_1),
            caughtException.getSuppressed()[0].getMessage()
    );
    Assert.assertNotNull(caughtException.getSuppressed()[0].getCause());
    Assert.assertTrue(caughtException.getSuppressed()[0].getCause() instanceof TslDownloadException);
    Assert.assertEquals("Exception message", caughtException.getSuppressed()[0].getCause().getMessage());
    Assert.assertArrayEquals(new Throwable[0], caughtException.getSuppressed()[0].getSuppressed());

    Assert.assertTrue(caughtException.getSuppressed()[1] instanceof TslParsingException);
    Assert.assertEquals(
            String.format("(Re)parsing needed for TL: %s", TL_URL_1),
            caughtException.getSuppressed()[1].getMessage()
    );

    Assert.assertTrue(caughtException.getSuppressed()[2] instanceof TslValidationException);
    Assert.assertEquals(
            String.format("(Re)validation needed for TL: %s", TL_URL_1),
            caughtException.getSuppressed()[2].getMessage()
    );
  }

  @Test
  public void testSingleLOTLInfoWithRequiredTLInfoWithParsingErrorAndValidationRefreshNeeded() {
    TLInfo tlInfo = new TLInfo(
            withState(new DownloadCacheDTO(), CacheStateEnum.SYNCHRONIZED),
            withErrorState(new ParsingCacheDTO(), "Exception message"),
            withState(new ValidationCacheDTO(), CacheStateEnum.REFRESH_NEEDED),
            TL_URL_3
    );

    TslRefreshException caughtException = testSingleLOTLInfoWithRequiredTLInfoThrowingException(tlInfo, TERRITORY_4);

    Assert.assertNull(caughtException.getCause());
    Assert.assertNotNull(caughtException.getSuppressed());
    Assert.assertEquals(2, caughtException.getSuppressed().length);

    Assert.assertTrue(caughtException.getSuppressed()[0] instanceof TslParsingException);
    Assert.assertEquals(
            String.format("Failed to parse TL: %s", TL_URL_3),
            caughtException.getSuppressed()[0].getMessage()
    );
    Assert.assertNotNull(caughtException.getSuppressed()[0].getCause());
    Assert.assertTrue(caughtException.getSuppressed()[0].getCause() instanceof TslParsingException);
    Assert.assertEquals("Exception message", caughtException.getSuppressed()[0].getCause().getMessage());
    Assert.assertArrayEquals(new Throwable[0], caughtException.getSuppressed()[0].getSuppressed());

    Assert.assertTrue(caughtException.getSuppressed()[1] instanceof TslValidationException);
    Assert.assertEquals(
            String.format("(Re)validation needed for TL: %s", TL_URL_3),
            caughtException.getSuppressed()[1].getMessage()
    );
  }

  private TslRefreshException testSingleLOTLInfoWithRequiredTLInfoThrowingException(TLInfo tlInfo, String requiredTerritory) {
    Mockito.doReturn(Collections.singletonList(requiredTerritory)).when(configuration).getRequiredTerritories();
    LOTLInfo lotlInfo = createValidLOTLInfo(TERRITORY_1, LOTL_URL_1);
    lotlInfo.setTlInfos(Arrays.asList(
            createValidTLInfo("UNRELATED_TERRITORY_1", "http://unrelated.tl.1"),
            tlInfo,
            createValidTLInfo("UNRELATED_TERRITORY_1", "http://unrelated.tl.2")
    ));

    TslRefreshException caughtException = testSingleLOTLInfoThrowingException(lotlInfo, TslRefreshException.class);

    Assert.assertEquals(
            String.format("Failed to load trusted lists for required territories: %s", requiredTerritory),
            caughtException.getMessage()
    );

    Mockito.verify(configuration).getRequiredTerritories();
    Mockito.verify(configuration).getTrustedTerritories();
    Mockito.verifyNoMoreInteractions(configuration);

    return caughtException;
  }

  @Test
  public void testSingleLOTLInfoWithSingleTLInfoSucceeds() {
    LOTLInfo lotlInfo = createValidLOTLInfo(TERRITORY_1, LOTL_URL_1);
    lotlInfo.setTlInfos(Collections.singletonList(
            createValidTLInfo(TERRITORY_2, TL_URL_1)
    ));

    testSummaryWithValidLOTLInfos(Collections.singletonList(lotlInfo));

    Mockito.verify(configuration).getRequiredTerritories();
    Mockito.verifyNoMoreInteractions(configuration);
  }

  @Test
  public void testSingleLOTLInfoWithMultipleTLInfosSucceeds() {
    LOTLInfo lotlInfo = createValidLOTLInfo(TERRITORY_1, LOTL_URL_1);
    lotlInfo.setTlInfos(Arrays.asList(
            createValidTLInfo(TERRITORY_2, TL_URL_1),
            createValidTLInfo(TERRITORY_3, TL_URL_2)
    ));

    testSummaryWithValidLOTLInfos(Collections.singletonList(lotlInfo));

    Mockito.verify(configuration).getRequiredTerritories();
    Mockito.verifyNoMoreInteractions(configuration);
  }

  @Test
  public void testSingleLOTLInfoWithMultipleTLInfosAtLeastOneSucceeds() {
    LOTLInfo lotlInfo = createValidLOTLInfo(TERRITORY_1, LOTL_URL_1);
    lotlInfo.setTlInfos(Arrays.asList(
            createValidTLInfo(TERRITORY_2, TL_URL_1),
            new TLInfo(
                    withErrorState(new DownloadCacheDTO(), "Exception message"),
                    withState(new ParsingCacheDTO(), CacheStateEnum.REFRESH_NEEDED),
                    withState(new ValidationCacheDTO(), CacheStateEnum.REFRESH_NEEDED),
                    TL_URL_2
            )
    ));

    testSummaryWithValidLOTLInfos(Collections.singletonList(lotlInfo));

    Mockito.verify(configuration).getRequiredTerritories();
    Mockito.verifyNoMoreInteractions(configuration);
  }

  @Test
  public void testMatchingRequiredTerritoriesWithoutTrustedTerritoriesSucceeds() {
    Mockito.doReturn(Arrays.asList(TERRITORY_2, TERRITORY_3)).when(configuration).getRequiredTerritories();
    LOTLInfo lotlInfo = createValidLOTLInfo(TERRITORY_1, LOTL_URL_1);
    lotlInfo.setTlInfos(Arrays.asList(
            createValidTLInfo(TERRITORY_2, TL_URL_1),
            createValidTLInfo(TERRITORY_3, TL_URL_2)
    ));

    testSummaryWithValidLOTLInfos(Collections.singletonList(lotlInfo));

    Mockito.verify(configuration).getRequiredTerritories();
    Mockito.verify(configuration).getTrustedTerritories();
    Mockito.verifyNoMoreInteractions(configuration);
  }

  @Test
  public void testOnlyTLInfosWithMatchingRequiredTerritoriesSucceeds() {
    Mockito.doReturn(Collections.singletonList(TERRITORY_2)).when(configuration).getRequiredTerritories();
    LOTLInfo lotlInfo = createValidLOTLInfo(TERRITORY_1, LOTL_URL_1);
    lotlInfo.setTlInfos(Arrays.asList(
            createValidTLInfo(TERRITORY_2, TL_URL_1),
            new TLInfo(
                    withErrorState(new DownloadCacheDTO(), "Exception message"),
                    withState(new ParsingCacheDTO(), CacheStateEnum.REFRESH_NEEDED),
                    withState(new ValidationCacheDTO(), CacheStateEnum.REFRESH_NEEDED),
                    TL_URL_2
            )
    ));

    testSummaryWithValidLOTLInfos(Collections.singletonList(lotlInfo));

    Mockito.verify(configuration).getRequiredTerritories();
    Mockito.verify(configuration).getTrustedTerritories();
    Mockito.verifyNoMoreInteractions(configuration);
  }

  @Test
  public void testMatchingRequiredTerritoriesAndMatchingTrustedTerritoriesSucceeds() {
    Mockito.doReturn(Arrays.asList(TERRITORY_2, TERRITORY_3)).when(configuration).getRequiredTerritories();
    Mockito.doReturn(Arrays.asList(TERRITORY_2, TERRITORY_3)).when(configuration).getTrustedTerritories();
    LOTLInfo lotlInfo = createValidLOTLInfo(TERRITORY_1, LOTL_URL_1);
    lotlInfo.setTlInfos(Arrays.asList(
            createValidTLInfo(TERRITORY_2, TL_URL_1),
            createValidTLInfo(TERRITORY_3, TL_URL_2)
    ));

    testSummaryWithValidLOTLInfos(Collections.singletonList(lotlInfo));

    Mockito.verify(configuration).getRequiredTerritories();
    Mockito.verify(configuration).getTrustedTerritories();
    Mockito.verifyNoMoreInteractions(configuration);
  }

  @Test
  public void testNonMatchingRequiredTerritoriesAndMatchingTrustedTerritoriesSucceeds() {
    Mockito.doReturn(Collections.singletonList("NO")).when(configuration).getRequiredTerritories();
    Mockito.doReturn(Arrays.asList(TERRITORY_2, TERRITORY_3)).when(configuration).getTrustedTerritories();
    LOTLInfo lotlInfo = createValidLOTLInfo(TERRITORY_1, LOTL_URL_1);
    lotlInfo.setTlInfos(Arrays.asList(
            createValidTLInfo(TERRITORY_2, TL_URL_1),
            createValidTLInfo(TERRITORY_3, TL_URL_2)
    ));

    testSummaryWithValidLOTLInfos(Collections.singletonList(lotlInfo));

    Mockito.verify(configuration).getRequiredTerritories();
    Mockito.verify(configuration).getTrustedTerritories();
    Mockito.verifyNoMoreInteractions(configuration);
  }

  private void testSummaryWithValidLOTLInfos(List<LOTLInfo> lotlInfos) {
    TLValidationJobSummary summary = new TLValidationJobSummary(lotlInfos, null);
    tslRefreshCallback.ensureTSLState(summary);
  }

  private static LOTLInfo createValidLOTLInfo(String territory, String url) {
    return new LOTLInfo(
            withState(new DownloadCacheDTO(), CacheStateEnum.SYNCHRONIZED),
            withSynchronizedState(new ParsingCacheDTO(), territory),
            withSynchronizedState(new ValidationCacheDTO(), Indication.TOTAL_PASSED),
            url
    );
  }

  private static TLInfo createValidTLInfo(String territory, String url) {
    return new TLInfo(
            withState(new DownloadCacheDTO(), CacheStateEnum.SYNCHRONIZED),
            withSynchronizedState(new ParsingCacheDTO(), territory),
            withSynchronizedState(new ValidationCacheDTO(), Indication.TOTAL_PASSED),
            url
    );
  }

  private static <T extends AbstractCacheDTO> T withState(T cacheInfo, CacheStateEnum state) {
    cacheInfo.setCacheState(state);
    return cacheInfo;
  }

  private static <T extends AbstractCacheDTO> T withErrorState(T cacheInfo, String exceptionMessage) {
    cacheInfo.setExceptionMessage(exceptionMessage);
    return withState(cacheInfo, CacheStateEnum.ERROR);
  }

  private static ParsingCacheDTO withSynchronizedState(ParsingCacheDTO cacheInfo, String territory) {
    cacheInfo.setTerritory(territory);
    return withState(cacheInfo, CacheStateEnum.SYNCHRONIZED);
  }

  private static ValidationCacheDTO withSynchronizedState(ValidationCacheDTO cacheInfo, Indication indication, SubIndication subIndication) {
    cacheInfo.setIndication(indication);
    cacheInfo.setSubIndication(subIndication);
    return withState(cacheInfo, CacheStateEnum.SYNCHRONIZED);
  }

  private static ValidationCacheDTO withSynchronizedState(ValidationCacheDTO cacheInfo, Indication indication) {
    return withSynchronizedState(cacheInfo, indication, null);
  }

  private static List<CacheStateEnum> unexpectedCacheStates() {
    return Stream.of(CacheStateEnum.values())
            .filter(state -> !CacheStateEnum.ERROR.equals(state))
            .filter(state -> !CacheStateEnum.REFRESH_NEEDED.equals(state))
            .filter(state -> !CacheStateEnum.SYNCHRONIZED.equals(state))
            .collect(Collectors.toList());
  }

  private static List<Indication> nonValidIndications() {
    return Stream.of(Indication.values())
            .filter(indication -> !Indication.TOTAL_PASSED.equals(indication))
            .collect(Collectors.toList());
  }

}
