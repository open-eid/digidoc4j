/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.sameInstance;

public abstract class AbstractTimestampBuilderTest extends AbstractTest {

  protected static final String TSP_SERVICE_URL = "http://host/path";

  protected abstract Container getDefaultContainerForTimestamping(Configuration configuration);

  @Test
  public void getReferenceDigestAlgorithm_WhenDefaultProdConfigurationIsUsed_ReturnsSha512() {
    getReferenceDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedAlgorithm(
            Configuration.of(Configuration.Mode.PROD),
            DigestAlgorithm.SHA512
    );
  }

  @Test
  public void getReferenceDigestAlgorithm_WhenDefaultTestConfigurationIsUsed_ReturnsSha512() {
    getReferenceDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedAlgorithm(
            Configuration.of(Configuration.Mode.TEST),
            DigestAlgorithm.SHA512
    );
  }

  @Test
  public void getReferenceDigestAlgorithm_WhenProdConfigurationWithSha1ReferenceDigestAlgorithmIsUsed_ReturnsSha1() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    configuration.setArchiveTimestampDigestAlgorithm(DigestAlgorithm.SHA224);
    configuration.setArchiveTimestampReferenceDigestAlgorithm(DigestAlgorithm.SHA1);
    getReferenceDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedAlgorithm(
            configuration,
            DigestAlgorithm.SHA1
    );
  }

  @Test
  public void getReferenceDigestAlgorithm_WhenTestConfigurationWithSha1ReferenceDigestAlgorithmIsUsed_ReturnsSha1() {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setArchiveTimestampDigestAlgorithm(DigestAlgorithm.SHA224);
    configuration.setArchiveTimestampReferenceDigestAlgorithm(DigestAlgorithm.SHA1);
    getReferenceDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedAlgorithm(
            configuration,
            DigestAlgorithm.SHA1
    );
  }

  @Test
  public void getReferenceDigestAlgorithm_WhenProdConfigurationWithSha224AlgorithmIsUsedWithoutReferenceConfigured_ReturnsSha224() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    configuration.setArchiveTimestampDigestAlgorithm(DigestAlgorithm.SHA224);
    getReferenceDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedAlgorithm(
            configuration,
            DigestAlgorithm.SHA224
    );
  }

  @Test
  public void getReferenceDigestAlgorithm_WhenTestConfigurationWithSha224AlgorithmIsUsedWithoutReferenceConfigured_ReturnsSha1() {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setArchiveTimestampDigestAlgorithm(DigestAlgorithm.SHA224);
    getReferenceDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedAlgorithm(
            configuration,
            DigestAlgorithm.SHA224
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void getReferenceDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedAlgorithm(
          Configuration configuration,
          DigestAlgorithm expectedAlgorithm
  ) {
    TimestampBuilder timestampBuilder = TimestampBuilder
            .aTimestamp(getDefaultContainerForTimestamping(configuration));

    DigestAlgorithm result = timestampBuilder.getReferenceDigestAlgorithm();

    assertThat(result, sameInstance(expectedAlgorithm));
  }

  @Test
  public void getReferenceDigestAlgorithm_WhenDefaultProdConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm() {
    getReferenceDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm(
            Configuration.of(Configuration.Mode.PROD)
    );
  }

  @Test
  public void getReferenceDigestAlgorithm_WhenDefaultTestConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm() {
    getReferenceDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm(
            Configuration.of(Configuration.Mode.TEST)
    );
  }

  @Test
  public void getReferenceDigestAlgorithm_WhenProdConfigurationWithChangesIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    configuration.setArchiveTimestampDigestAlgorithm(DigestAlgorithm.SHA224);
    configuration.setArchiveTimestampReferenceDigestAlgorithm(DigestAlgorithm.SHA224);
    getReferenceDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm(
            configuration
    );
  }

  @Test
  public void getReferenceDigestAlgorithm_WhenTestConfigurationWithChangesIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm() {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setArchiveTimestampDigestAlgorithm(DigestAlgorithm.SHA224);
    configuration.setArchiveTimestampReferenceDigestAlgorithm(DigestAlgorithm.SHA224);
    getReferenceDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm(
            configuration
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void getReferenceDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm(
          Configuration configuration
  ) {
    TimestampBuilder timestampBuilder = TimestampBuilder
            .aTimestamp(getDefaultContainerForTimestamping(configuration))
            .withReferenceDigestAlgorithm(DigestAlgorithm.SHA1);

    DigestAlgorithm result = timestampBuilder.getReferenceDigestAlgorithm();

    assertThat(result, sameInstance(DigestAlgorithm.SHA1));
  }

  @Test
  public void getTimestampDigestAlgorithm_WhenDefaultProdConfigurationIsUsed_ReturnsSha512() {
    getTimestampDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedAlgorithm(
            Configuration.of(Configuration.Mode.PROD),
            DigestAlgorithm.SHA512
    );
  }

  @Test
  public void getTimestampDigestAlgorithm_WhenDefaultTestConfigurationIsUsed_ReturnsSha512() {
    getTimestampDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedAlgorithm(
            Configuration.of(Configuration.Mode.TEST),
            DigestAlgorithm.SHA512
    );
  }

  @Test
  public void getTimestampDigestAlgorithm_WhenProdConfigurationWithSha1TimestampDigestAlgorithmIsUsed_ReturnsSha1() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    configuration.setArchiveTimestampDigestAlgorithm(DigestAlgorithm.SHA1);
    getTimestampDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedAlgorithm(
            configuration,
            DigestAlgorithm.SHA1
    );
  }

  @Test
  public void getTimestampDigestAlgorithm_WhenTestConfigurationWithSha1TimestampDigestAlgorithmIsUsed_ReturnsSha1() {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setArchiveTimestampDigestAlgorithm(DigestAlgorithm.SHA1);
    getTimestampDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedAlgorithm(
            configuration,
            DigestAlgorithm.SHA1
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void getTimestampDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedAlgorithm(
          Configuration configuration,
          DigestAlgorithm expectedAlgorithm
  ) {
    TimestampBuilder timestampBuilder = TimestampBuilder
            .aTimestamp(getDefaultContainerForTimestamping(configuration));

    DigestAlgorithm result = timestampBuilder.getTimestampDigestAlgorithm();

    assertThat(result, sameInstance(expectedAlgorithm));
  }

  @Test
  public void getTimestampDigestAlgorithm_WhenDefaultProdConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm() {
    getTimestampDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm(
            Configuration.of(Configuration.Mode.PROD)
    );
  }

  @Test
  public void getTimestampDigestAlgorithm_WhenDefaultTestConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm() {
    getTimestampDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm(
            Configuration.of(Configuration.Mode.TEST)
    );
  }

  @Test
  public void getTimestampDigestAlgorithm_WhenProdConfigurationWithChangesIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    configuration.setArchiveTimestampDigestAlgorithm(DigestAlgorithm.SHA224);
    getTimestampDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm(
            configuration
    );
  }

  @Test
  public void getTimestampDigestAlgorithm_WhenTestConfigurationWithChangesIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm() {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setArchiveTimestampDigestAlgorithm(DigestAlgorithm.SHA224);
    getTimestampDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm(
            configuration
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void getTimestampDigestAlgorithm_WhenSpecifiedConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenAlgorithm(
          Configuration configuration
  ) {
    TimestampBuilder timestampBuilder = TimestampBuilder
            .aTimestamp(getDefaultContainerForTimestamping(configuration))
            .withTimestampDigestAlgorithm(DigestAlgorithm.SHA1);

    DigestAlgorithm result = timestampBuilder.getTimestampDigestAlgorithm();

    assertThat(result, sameInstance(DigestAlgorithm.SHA1));
  }

  @Test
  public void getTspSource_WhenDefaultProdConfigurationIsUsed_ReturnsDefaultProdTspSource() {
    getTspSource_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedServiceUrl(
            Configuration.of(Configuration.Mode.PROD),
            Constant.Production.TSP_SOURCE
    );
  }

  @Test
  public void getTspSource_WhenDefaultTestConfigurationIsUsed_ReturnsDefaultTestTspSource() {
    getTspSource_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedServiceUrl(
            Configuration.of(Configuration.Mode.TEST),
            Constant.Test.TSP_SOURCE
    );
  }

  @Test
  public void getTspSource_WhenProdConfigurationWithSpecifiedTspSourceIsUsed_ReturnsTheSpecifiedTspSource() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    configuration.setTspSource(TSP_SERVICE_URL);
    getTspSource_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedServiceUrl(
            configuration,
            TSP_SERVICE_URL
    );
  }

  @Test
  public void getTspSource_WhenTestConfigurationWithSpecifiedTspSourceIsUsed_ReturnsTheSpecifiedTspSource() {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setTspSource(TSP_SERVICE_URL);
    getTspSource_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedServiceUrl(
            configuration,
            TSP_SERVICE_URL
    );
  }

  @Test
  public void getTspSource_WhenProdConfigurationWithSpecifiedArchiveTspSourceIsUsed_ReturnsTheSpecifiedTspSource() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    configuration.setTspSourceForArchiveTimestamps(TSP_SERVICE_URL);
    getTspSource_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedServiceUrl(
            configuration,
            TSP_SERVICE_URL
    );
  }

  @Test
  public void getTspSource_WhenTestConfigurationWithSpecifiedArchiveTspSourceIsUsed_ReturnsTheSpecifiedTspSource() {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setTspSourceForArchiveTimestamps(TSP_SERVICE_URL);
    getTspSource_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedServiceUrl(
            configuration,
            TSP_SERVICE_URL
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void getTspSource_WhenSpecifiedConfigurationIsUsedWithoutBuilderOverrides_ReturnsExpectedServiceUrl(
          Configuration configuration,
          String expectedServiceUrl
  ) {
    TimestampBuilder timestampBuilder = TimestampBuilder
            .aTimestamp(getDefaultContainerForTimestamping(configuration));

    String result = timestampBuilder.getTspSource();

    assertThat(result, equalTo(expectedServiceUrl));
  }

  @Test
  public void getTspSource_WhenDefaultProdConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenServiceUrl() {
    getTspSource_WhenSpecifiedConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenServiceUrl(
            Configuration.of(Configuration.Mode.PROD)
    );
  }

  @Test
  public void getTspSource_WhenDefaultTestConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenServiceUrl() {
    getTspSource_WhenSpecifiedConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenServiceUrl(
            Configuration.of(Configuration.Mode.TEST)
    );
  }

  @Test
  public void getTspSource_WhenProdConfigurationWithSpecifiedTspSourceIsUsedWithBuilderOverrides_ReturnsOverriddenServiceUrl() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    configuration.setTspSource(TSP_SERVICE_URL);
    getTspSource_WhenSpecifiedConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenServiceUrl(
            configuration
    );
  }

  @Test
  public void getTspSource_WhenTestConfigurationWithSpecifiedTspSourceIsUsedWithBuilderOverrides_ReturnsOverriddenServiceUrl() {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setTspSource(TSP_SERVICE_URL);
    getTspSource_WhenSpecifiedConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenServiceUrl(
            configuration
    );
  }

  @Test
  public void getTspSource_WhenProdConfigurationWithSpecifiedArchiveTspSourceIsUsedWithBuilderOverrides_ReturnsOverriddenServiceUrl() {
    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
    configuration.setTspSourceForArchiveTimestamps(TSP_SERVICE_URL);
    getTspSource_WhenSpecifiedConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenServiceUrl(
            configuration
    );
  }

  @Test
  public void getTspSource_WhenTestConfigurationWithSpecifiedArchiveTspSourceIsUsedWithBuilderOverrides_ReturnsOverriddenServiceUrl() {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setTspSourceForArchiveTimestamps(TSP_SERVICE_URL);
    getTspSource_WhenSpecifiedConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenServiceUrl(
            configuration
    );
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void getTspSource_WhenSpecifiedConfigurationIsUsedWithBuilderOverrides_ReturnsOverriddenServiceUrl(
          Configuration configuration
  ) {
    TimestampBuilder timestampBuilder = TimestampBuilder
            .aTimestamp(getDefaultContainerForTimestamping(configuration))
            .withTspSource("http://overridden.host/path");

    String result = timestampBuilder.getTspSource();

    assertThat(result, equalTo("http://overridden.host/path"));
  }

}
