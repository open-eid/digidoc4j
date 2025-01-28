/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.TSPSourceFactory;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.function.Function;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class ArchiveTspSourceFactoryTest extends AbstractTest {

  private static final String SERVICE_URL = "http://host/path";

  @Test
  public void create_WhenCustomSourceFactoryIsConfiguredAndNoPreferredLanguage_ReturnsCustomTspSource() {
    create_WhenCustomSourceFactoryIsConfigured_ReturnsCustomTspSource(ArchiveTspSourceFactory::new);
  }

  @Test
  public void create_WhenCustomSourceFactoryIsConfiguredAndServiceUrlOverrideIsNull_ReturnsCustomTspSource() {
    create_WhenCustomSourceFactoryIsConfigured_ReturnsCustomTspSource(
            configuration -> new ArchiveTspSourceFactory(configuration, null)
    );
  }

  @Test
  public void create_WhenCustomSourceFactoryIsConfiguredAndServiceUrlOverrideIsPresent_ReturnsCustomTspSource() {
    create_WhenCustomSourceFactoryIsConfigured_ReturnsCustomTspSource(
            configuration -> new ArchiveTspSourceFactory(configuration, SERVICE_URL)
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void create_WhenCustomSourceFactoryIsConfigured_ReturnsCustomTspSource(
          Function<Configuration, ArchiveTspSourceFactory> archiveTspSourceFactoryResolver
  ) {
    Configuration configurationMock = mock(Configuration.class);
    TSPSourceFactory tspSourceFactoryMock = mock(TSPSourceFactory.class);
    doReturn(tspSourceFactoryMock).when(configurationMock).getArchiveTspSourceFactory();
    TSPSource tspSourceMock = mock(TSPSource.class);
    doReturn(tspSourceMock).when(tspSourceFactoryMock).create();
    ArchiveTspSourceFactory archiveTspSourceFactory = archiveTspSourceFactoryResolver.apply(configurationMock);

    TSPSource result = archiveTspSourceFactory.create();

    assertThat(result, sameInstance(tspSourceMock));
    verify(configurationMock).getArchiveTspSourceFactory();
    verify(tspSourceFactoryMock).create();
    verifyNoMoreInteractions(configurationMock, tspSourceFactoryMock);
    verifyNoInteractions(tspSourceMock);
  }

  @Test
  public void create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideNotSetAndDefaultTestConfigurationUsed_ReturnsOnlineTspSourceWithDefaultUrl() throws Exception {
    create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideNotSet_ReturnsOnlineTspSourceThatUsesExpectedServiceUrl(
            Configuration.of(Configuration.Mode.TEST),
            Constant.Test.TSP_SOURCE
    );
  }

  @Test
  public void create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideNotSetAndDefaultProdConfigurationUsed_ReturnsOnlineTspSourceWithDefaultUrl() throws Exception {
    create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideNotSet_ReturnsOnlineTspSourceThatUsesExpectedServiceUrl(
            Configuration.of(Configuration.Mode.PROD),
            Constant.Production.TSP_SOURCE
    );
  }

  @Test
  public void create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideNotSetAndTestConfigurationWithArchiveTspUrlUsed_ReturnsOnlineTspSourceWithDefaultUrl() throws Exception {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setTspSourceForArchiveTimestamps(SERVICE_URL);
    create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideNotSet_ReturnsOnlineTspSourceThatUsesExpectedServiceUrl(
            configuration,
            SERVICE_URL
    );
  }

  @Test
  public void create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideNotSetAndProdConfigurationWithArchiveTspUrlUsed_ReturnsOnlineTspSourceWithDefaultUrl() throws Exception {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    configuration.setTspSourceForArchiveTimestamps(SERVICE_URL);
    create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideNotSet_ReturnsOnlineTspSourceThatUsesExpectedServiceUrl(
            configuration,
            SERVICE_URL
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideNotSet_ReturnsOnlineTspSourceThatUsesExpectedServiceUrl(
          Configuration configuration,
          String expectedServiceUrl
  ) throws Exception {
    DataLoader dataLoaderMock = mock(DataLoader.class);
    configuration.setTspDataLoaderFactory(() -> dataLoaderMock);
    ArchiveTspSourceFactory tspSourceFactory = new ArchiveTspSourceFactory(configuration);

    TSPSource result = tspSourceFactory.create();

    assertThat(result, notNullValue());
    assertThat(result, instanceOf(OnlineTSPSource.class));
    verifyNoInteractions(dataLoaderMock);
    verifyDataLoaderIsUsed(result, dataLoaderMock, expectedServiceUrl);
  }

  @Test
  public void create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideIsSetAndDefaultTestConfigurationUsed_ReturnsOnlineTspSourceWithOverriddenUrl() throws Exception {
    create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideIsSet_ReturnsOnlineTspSourceThatUsesOverriddenServiceUrl(
            Configuration.of(Configuration.Mode.TEST)
    );
  }

  @Test
  public void create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideIsSetAndDefaultProdConfigurationUsed_ReturnsOnlineTspSourceWithOverriddenUrl() throws Exception {
    create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideIsSet_ReturnsOnlineTspSourceThatUsesOverriddenServiceUrl(
            Configuration.of(Configuration.Mode.PROD)
    );
  }

  @Test
  public void create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideIsSetAndTestConfigurationWithArchiveTspUrlUsed_ReturnsOnlineTspSourceWithOverriddenUrl() throws Exception {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setTspSourceForArchiveTimestamps("http://archive.tsp/path");
    create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideIsSet_ReturnsOnlineTspSourceThatUsesOverriddenServiceUrl(
            configuration
    );
  }

  @Test
  public void create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideIsSetAndProdConfigurationWithArchiveTspUrlUsed_ReturnsOnlineTspSourceWithOverriddenUrl() throws Exception {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    configuration.setTspSourceForArchiveTimestamps("http://archive.tsp/path");
    create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideIsSet_ReturnsOnlineTspSourceThatUsesOverriddenServiceUrl(
            configuration
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void create_WhenNoSourceFactoryConfiguredAndServiceUrlOverrideIsSet_ReturnsOnlineTspSourceThatUsesOverriddenServiceUrl(
          Configuration configuration
  ) throws Exception {
    DataLoader dataLoaderMock = mock(DataLoader.class);
    configuration.setTspDataLoaderFactory(() -> dataLoaderMock);
    ArchiveTspSourceFactory tspSourceFactory = new ArchiveTspSourceFactory(configuration, SERVICE_URL);

    TSPSource result = tspSourceFactory.create();

    assertThat(result, notNullValue());
    assertThat(result, instanceOf(OnlineTSPSource.class));
    verifyNoInteractions(dataLoaderMock);
    verifyDataLoaderIsUsed(result, dataLoaderMock, SERVICE_URL);
  }

  private void verifyDataLoaderIsUsed(TSPSource tspSource, DataLoader tspDataLoaderMock, String expectedUrl) throws Exception {
    DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
    byte[] digest = digestAlgorithm.getMessageDigest()
            .digest("Data to digest.".getBytes(StandardCharsets.UTF_8));
    // Positive response requires a valid timestamp response with a matching nonce,
    //  so, for simplicity, just throw an exception in the data loader.
    CustomException customException = new CustomException();
    doThrow(customException).when(tspDataLoaderMock).post(eq(expectedUrl), any(byte[].class));

    CustomException caughtException = assertThrows(
            CustomException.class,
            () -> tspSource.getTimeStampResponse(digestAlgorithm, digest)
    );

    assertThat(caughtException, sameInstance(customException));
    verify(tspDataLoaderMock).post(eq(expectedUrl), any(byte[].class));
    verifyNoMoreInteractions(tspDataLoaderMock);
  }

  private static class CustomException extends RuntimeException {
  }

}
