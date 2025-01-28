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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
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

public class SignatureTspSourceFactoryTest extends AbstractTest {

  private static final String COUNTRY = "CUSTOM_COUNTRY_CODE";
  private static final String SERVICE_URL = "http://host/path";

  @Test
  public void create_WhenCustomSourceFactoryIsConfiguredAndNoPreferredLanguage_ReturnsCustomTspSource() {
    create_WhenCustomSourceFactoryIsConfigured_ReturnsCustomTspSource(SignatureTspSourceFactory::new);
  }

  @Test
  public void create_WhenCustomSourceFactoryIsConfiguredAndPreferredLanguageIsNull_ReturnsCustomTspSource() {
    create_WhenCustomSourceFactoryIsConfigured_ReturnsCustomTspSource(
            configuration -> new SignatureTspSourceFactory(configuration, null)
    );
  }

  @Test
  public void create_WhenCustomSourceFactoryIsConfiguredAndPreferredLanguageIsPresent_ReturnsCustomTspSource() {
    create_WhenCustomSourceFactoryIsConfigured_ReturnsCustomTspSource(
            configuration -> new SignatureTspSourceFactory(configuration, COUNTRY)
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void create_WhenCustomSourceFactoryIsConfigured_ReturnsCustomTspSource(
          Function<Configuration, SignatureTspSourceFactory> signatureTspSourceFactoryResolver
  ) {
    Configuration configurationMock = mock(Configuration.class);
    TSPSourceFactory tspSourceFactoryMock = mock(TSPSourceFactory.class);
    doReturn(tspSourceFactoryMock).when(configurationMock).getSignatureTspSourceFactory();
    TSPSource tspSourceMock = mock(TSPSource.class);
    doReturn(tspSourceMock).when(tspSourceFactoryMock).create();
    SignatureTspSourceFactory signatureTspSourceFactory = signatureTspSourceFactoryResolver.apply(configurationMock);

    TSPSource result = signatureTspSourceFactory.create();

    assertThat(result, sameInstance(tspSourceMock));
    verify(configurationMock).getSignatureTspSourceFactory();
    verify(tspSourceFactoryMock).create();
    verifyNoMoreInteractions(configurationMock, tspSourceFactoryMock);
    verifyNoInteractions(tspSourceMock);
  }

  @Test
  public void create_WhenNoSourceFactoryConfiguredAndPreferredCountryNotSetAndDefaultTestConfigurationUsed_ReturnsOnlineTspSource() throws Exception {
    create_WhenNoSourceFactoryConfiguredAndPreferredCountryNotSet_ReturnsOnlineTspSourceThatUsesExpectedServiceUrl(
            Configuration.of(Configuration.Mode.TEST),
            Constant.Test.TSP_SOURCE
    );
  }

  @Test
  public void create_WhenNoSourceFactoryConfiguredAndPreferredCountryNotSetAndDefaultProdConfigurationUsed_ReturnsOnlineTspSource() throws Exception {
    create_WhenNoSourceFactoryConfiguredAndPreferredCountryNotSet_ReturnsOnlineTspSourceThatUsesExpectedServiceUrl(
            Configuration.of(Configuration.Mode.PROD),
            Constant.Production.TSP_SOURCE
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void create_WhenNoSourceFactoryConfiguredAndPreferredCountryNotSet_ReturnsOnlineTspSourceThatUsesExpectedServiceUrl(
          Configuration configuration,
          String expectedServiceUrl
  ) throws Exception {
    DataLoader dataLoaderMock = mock(DataLoader.class);
    configuration.setTspDataLoaderFactory(() -> dataLoaderMock);
    SignatureTspSourceFactory tspSourceFactory = new SignatureTspSourceFactory(configuration);

    TSPSource result = tspSourceFactory.create();

    assertThat(result, notNullValue());
    assertThat(result, instanceOf(OnlineTSPSource.class));
    verifyNoInteractions(dataLoaderMock);
    verifyDataLoaderIsUsed(result, dataLoaderMock, expectedServiceUrl);
  }

  @Test
  public void create_WhenNoSourceFactoryConfiguredAndPreferredCountryIsSetButNotFoundAndDefaultTestConfigurationUsed_ReturnsOnlineTspSource() throws Exception {
    create_WhenNoSourceFactoryConfiguredAndPreferredCountryIsSet_ReturnsOnlineTspSourceThatUsesExpectedServiceUrl(
            Configuration.of(Configuration.Mode.TEST),
            Constant.Test.TSP_SOURCE
    );
  }

  @Test
  public void create_WhenNoSourceFactoryConfiguredAndPreferredCountryIsSetButNotFoundAndDefaultProdConfigurationUsed_ReturnsOnlineTspSource() throws Exception {
    create_WhenNoSourceFactoryConfiguredAndPreferredCountryIsSet_ReturnsOnlineTspSourceThatUsesExpectedServiceUrl(
            Configuration.of(Configuration.Mode.PROD),
            Constant.Production.TSP_SOURCE
    );
  }

  @Test
  public void create_WhenNoSourceFactoryConfiguredAndPreferredCountryIsSetAndDefaultTestConfigurationUsed_ReturnsOnlineTspSourceWithCountryUrl() throws Exception {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    configureCountryTspSource(configuration);
    create_WhenNoSourceFactoryConfiguredAndPreferredCountryIsSet_ReturnsOnlineTspSourceThatUsesExpectedServiceUrl(
            configuration,
            SERVICE_URL
    );
  }

  @Test
  public void create_WhenNoSourceFactoryConfiguredAndPreferredCountryIsSetAndDefaultProdConfigurationUsed_ReturnsOnlineTspSourceWithCountryUrl() throws Exception {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    configureCountryTspSource(configuration);
    create_WhenNoSourceFactoryConfiguredAndPreferredCountryIsSet_ReturnsOnlineTspSourceThatUsesExpectedServiceUrl(
            configuration,
            SERVICE_URL
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void create_WhenNoSourceFactoryConfiguredAndPreferredCountryIsSet_ReturnsOnlineTspSourceThatUsesExpectedServiceUrl(
          Configuration configuration,
          String expectedServiceUrl
  ) throws Exception {
    DataLoader dataLoaderMock = mock(DataLoader.class);
    configuration.setTspDataLoaderFactory(() -> dataLoaderMock);
    SignatureTspSourceFactory tspSourceFactory = new SignatureTspSourceFactory(configuration, COUNTRY);

    TSPSource result = tspSourceFactory.create();

    assertThat(result, notNullValue());
    assertThat(result, instanceOf(OnlineTSPSource.class));
    verifyNoInteractions(dataLoaderMock);
    verifyDataLoaderIsUsed(result, dataLoaderMock, expectedServiceUrl);
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

  private static void configureCountryTspSource(Configuration configuration) {
    String configurationString = "TSPS:\n" +
            "  - TSP_C: " + COUNTRY + '\n' +
            "    TSP_SOURCE: " + SERVICE_URL +'\n' +
            "    TSP_KEYSTORE_PATH: unused\n" +
            "    TSP_KEYSTORE_TYPE: unused\n" +
            "    TSP_KEYSTORE_PASSWORD: unused";

    try (InputStream in = new ByteArrayInputStream(configurationString.getBytes(StandardCharsets.UTF_8))) {
      configuration.loadConfiguration(in);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to load configuration", e);
    }
  }

  private static class CustomException extends RuntimeException {
  }

}
