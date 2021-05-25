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

import eu.europa.esig.dss.spi.client.http.Protocol;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.digidoc4j.exceptions.ConfigurationException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.ConfigurationSingeltonHolder;
import org.digidoc4j.impl.asic.tsl.TslManager;
import org.digidoc4j.utils.ResourceUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ExecutorService;

import static java.util.Arrays.asList;

/**
 * Possibility to create custom configurations for {@link Container} implementations.
 * <p>
 * It is possible to get the default Configuration object used in all containers by using
 * {@link Configuration#getInstance()}. This will return a singelton Configuration object used by default
 * if no configuration is provided.
 * </p>
 * <p/>
 * You can specify the configuration mode, either {@link Configuration.Mode#TEST} or {@link Configuration.Mode#PROD}
 * configuration. Default is {@link Configuration.Mode#PROD}.
 * <p/>
 * <p>
 * It is a good idea to use only a single configuration object for all the containers so the operation times would be
 * faster.
 * </p>
 * It is also possible to set the mode using the System property. Setting the property "digidoc4j.mode" to "TEST" forces
 * the default mode to {@link Configuration.Mode#TEST} mode
 * <p/>
 * Configurations will be loaded from a file. The file must be in yaml format.<p/>
 * <p/>
 * <H3>Required entries of the configuration file:</H3>
 * The configuration file must contain one or more Certificate Authorities under the heading DIGIDOC_CAS
 * similar to following format (values are examples only):<br>
 * <p>
 * <pre>
 * DIGIDOC_CAS:
 * - DIGIDOC_CA:
 *     NAME: CA name
 *     TRADENAME: Tradename
 *     CERTS:
 *       - jar://certs/cert1.crt
 *       - jar://certs/cert2.crt
 *     OCSPS:
 * </pre>
 * <p/>
 * Each DIGIDOC_CA entry must contain one or more OCSP certificates under the heading "OCSPS"
 * similar to following format (values are examples only):<br>
 * <p>
 * <pre>
 *       - OCSP:
 *         CA_CN: your certificate authority common name
 *         CA_CERT: jar://your ca_cn.crt
 *         CN: your common name
 *         CERTS:
 *         - jar://certs/Your first OCSP Certifications file.crt
 *         - jar://certs/Your second OCSP Certifications file.crt
 *         URL: http://ocsp.test.test
 * </pre>
 * <p>All entries must exist and be valid. Under CERTS must be at least one entry.</p>
 * <p/>
 * <p/>
 * <H3>Optional entries of the configuration file:</H3>
 * <ul>
 * <li>CANONICALIZATION_FACTORY_IMPL: Canonicalization factory implementation.<br>
 * Default value: {@value Constant.DDoc4J#CANONICALIZATION_FACTORY_IMPLEMENTATION}</li>
 * <li>CONNECTION_TIMEOUT: TSL HTTP Connection timeout (milliseconds).<br>
 * Default value: 1000  </li>
 * <li>DIGIDOC_FACTORY_IMPL: Factory implementation.<br>
 * Default value: {@value Constant.DDoc4J#FACTORY_IMPLEMENTATION}</li>
 * <li>DIGIDOC_DF_CACHE_DIR: Temporary directory to use. Default: uses system's default temporary directory</li>
 * <li>DIGIDOC_MAX_DATAFILE_CACHED: Maximum datafile size that will be cached in MB.
 * Must be numeric. Set to -1 to cache all files. Set to 0 to prevent caching for all files<br>
 * Default value: {@value Constant.DDoc4J#MAX_DATAFILE_CACHED}</li>
 * <li>DIGIDOC_NOTARY_IMPL: Notary implementation.<br>
 * Default value: {@value Constant.DDoc4J#NOTARY_IMPLEMENTATION}</li>
 * <li>DIGIDOC_OCSP_SIGN_CERT_SERIAL: OCSP Signing certificate serial number</li>
 * <li>DIGIDOC_SECURITY_PROVIDER: Security provider.<br>
 * Default value: {@value Constant.DDoc4J#SECURITY_PROVIDER}</li>
 * <li>DIGIDOC_SECURITY_PROVIDER_NAME: Name of the security provider.<br>
 * Default value: {@value Constant.DDoc4J#SECURITY_PROVIDER_NAME}</li>
 * <li>DIGIDOC_TSLFAC_IMPL: TSL Factory implementation.<br>
 * Default value: {@value Constant.DDoc4J#TSL_FACTORY_IMPLEMENTATION}</li>
 * <li>DIGIDOC_USE_LOCAL_TSL: Use local TSL? Allowed values: true, false<br>
 * Default value: {@value Constant.DDoc4J#USE_LOCAL_TSL}</li>
 * <li>KEY_USAGE_CHECK: Should key usage be checked? Allowed values: true, false.<br>
 * Default value: {@value Constant.DDoc4J#KEY_USAGE_CHECK}</li>
 * <li>DIGIDOC_PKCS12_CONTAINER: OCSP access certificate file</li>
 * <li>DIGIDOC_PKCS12_PASSWD: OCSP access certificate password</li>
 * <li>OCSP_SOURCE: Online Certificate Service Protocol source</li>
 * <li>SIGN_OCSP_REQUESTS: Should OCSP requests be signed? Allowed values: true, false</li>
 * <li>TSL_LOCATION: TSL Location</li>
 * <li>TSP_SOURCE: Time Stamp Protocol source address</li>
 * <li>VALIDATION_POLICY: Validation policy source file</li>
 * <li>TSL_KEYSTORE_LOCATION: keystore location for tsl signing certificates</li>
 * <li>TSL_KEYSTORE_PASSWORD: keystore password for the keystore in TSL_KEYSTORE_LOCATION</li>
 * <li>TSL_CACHE_EXPIRATION_TIME: TSL cache expiration time in milliseconds</li>
 * <li>TRUSTED_TERRITORIES: list of countries and territories to trust and load TSL certificates
 * (for example, EE, LV, FR)</li>
 * <li>HTTP_PROXY_HOST: network proxy host name</li>
 * <li>HTTP_PROXY_PORT: network proxy port</li>
 * <li>HTTP_PROXY_USER: network proxy user (for basic auth proxy)</li>
 * <li>HTTP_PROXY_PASSWORD: network proxy password (for basic auth proxy)</li>
 * <li>HTTPS_PROXY_HOST: https network proxy host name</li>
 * <li>HTTPS_PROXY_PORT: https network proxy port</li>
 * <li>SSL_KEYSTORE_PATH: SSL KeyStore path</li>
 * <li>SSL_KEYSTORE_TYPE: SSL KeyStore type (default is "jks")</li>
 * <li>SSL_KEYSTORE_PASSWORD: SSL KeyStore password (default is an empty string)</li>
 * <li>SSL_TRUSTSTORE_PATH: SSL TrustStore path</li>
 * <li>SSL_TRUSTSTORE_TYPE: SSL TrustStore type (default is "jks")</li>
 * <li>SSL_TRUSTSTORE_PASSWORD: SSL TrustStore password (default is an empty string)</li>
 * <li>SSL_PROTOCOL: SSL protocol (default is "TLSv1.2")</li>
 * <li>SUPPORTED_SSL_PROTOCOLS: list of supported SSL protocols (by default uses implementation defaults)</li>
 * <li>SUPPORTED_SSL_CIPHER_SUITES: list of supported SSL cipher suites (by default uses implementation defaults)</li>
 * <li>ALLOWED_TS_AND_OCSP_RESPONSE_DELTA_IN_MINUTES: Allowed delay between timestamp and OCSP response in minutes.</li>
 * <li>TEMP_FILE_MAX_AGE: Maximum age in milliseconds till TEMP files are deleted (works only when saving container).</li>
 * <li>ALLOW_UNSAFE_INTEGER: Allows to use unsafe Integer because of few applications still struggle with the
 * ASN.1 BER encoding rules for an INTEGER as described in:
 * {@link https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf. }
 * NB! Strict Validation applied by default.</li>
 * <li>ALLOWED_OCSP_RESPONDERS_FOR_TM: whitelist of OCSP responders for timemark validation
 * (for example: SK OCSP RESPONDER 2011, ESTEID-SK OCSP RESPONDER, KLASS3-SK OCSP RESPONDER)</li>
 * </ul>
 */
public class Configuration implements Serializable {

  private static final Logger LOGGER = LoggerFactory.getLogger(Configuration.class);
  private final Mode mode;
  private transient ExecutorService threadExecutor;
  private TslManager tslManager;
  private Hashtable<String, String> ddoc4jConfiguration = new Hashtable<>();
  private ConfigurationRegistry registry = new ConfigurationRegistry();

  // TODO integrate tspMap and aiaOcspMap (multilevel arrays) into configuration registry
  private HashMap<String, Map<ConfigurationParameter, String>> tspMap = new HashMap<>();
  private HashMap<String, Map<ConfigurationParameter, String>> aiaOcspMap = new HashMap<>();

  private List<String> trustedTerritories = new ArrayList<>();
  private ArrayList<String> inputSourceParseErrors = new ArrayList<>();
  private LinkedHashMap<String, Object> configurationFromFile;
  private String configurationInputSourceName;

  private DataLoaderFactory ocspDataLoaderFactory;
  private DataLoaderFactory tspDataLoaderFactory;
  private DataLoaderFactory tslDataLoaderFactory;
  private DataLoaderFactory aiaDataLoaderFactory;

  /**
   * Application mode
   */
  public enum Mode {
    TEST("digidoc4j-test.yaml", "digidoc4j.yaml"),
    PROD("digidoc4j.yaml"),
    ;
    final String[] defaultConfigurationFiles;
    Mode(String... defaultConfigurationFiles) {
      this.defaultConfigurationFiles = defaultConfigurationFiles;
    }
  }

  /**
   * Getting the default Configuration object. <br/>
   * <p>
   * The default configuration object is a singelton, meaning that all the containers will use the same registry
   * object. It is a good idea to use only a single configuration object for all the containers so the operation times
   * would be faster.
   *
   * @return default configuration.
   */
  public static Configuration getInstance() {
    return ConfigurationSingeltonHolder.getInstance();
  }

  /**
   * Create new configuration in static context with application mode specified
   *
   * @param mode Application mode
   */
  public static Configuration of(Mode mode) {
    return new Configuration(mode);
  }

  /**
   * Create new configuration
   */
  public Configuration() {
    this(Mode.TEST.name().equalsIgnoreCase(System.getProperty("digidoc4j.mode")) ? Mode.TEST : Mode.PROD);
  }

  /**
   * Create new configuration with application mode specified
   *
   * @param mode Application mode
   */
  public Configuration(Mode mode) {
    if (LOGGER.isInfoEnabled() && !LOGGER.isDebugEnabled()) {
      LOGGER.info("DigiDoc4J will be executed in <{}> mode", mode);
    }
    LOGGER.debug("------------------------ <MODE: {}> ------------------------", mode);
    this.mode = mode;
    this.loadDefaultConfigurationFor(mode);
    this.initDefaultValues();
    LOGGER.debug("------------------------ </MODE: {}> ------------------------", mode);
    if (!LOGGER.isDebugEnabled()) {
      LOGGER.info("Configuration loaded ...");
    }
  }

  /**
   * Are requirements met for signing OCSP certificate?
   *
   * @return value indicating if requirements are met
   */
  public boolean isOCSPSigningConfigurationAvailable() {
    boolean available = StringUtils.isNotBlank(this.getOCSPAccessCertificateFileName())
        && this.getOCSPAccessCertificatePassword().length != 0;
    LOGGER.debug("Is OCSP signing configuration available? {}", available);
    return available;
  }

  /**
   * Get OCSP access certificate filename
   *
   * @return filename for the OCSP access certificate
   */
  public String getOCSPAccessCertificateFileName() {
    String ocspAccessCertificateFile = this.getConfigurationParameter(ConfigurationParameter.OcspAccessCertificateFile);
    return ocspAccessCertificateFile == null ? "" : ocspAccessCertificateFile;
  }

  /**
   * Get OSCP access certificate password
   *
   * @return password
   */
  public char[] getOCSPAccessCertificatePassword() {
    char[] result = {};
    String password = this.getConfigurationParameter(ConfigurationParameter.OcspAccessCertificatePassword);
    if (StringUtils.isNotEmpty(password)) {
      result = password.toCharArray();
    }
    return result;
  }

  /**
   * Get OSCP access certificate password As String
   *
   * @return password
   */
  public String getOCSPAccessCertificatePasswordAsString() {
    return this.getConfigurationParameter(ConfigurationParameter.OcspAccessCertificatePassword);
  }

  /**
   * Set OCSP access certificate filename
   *
   * @param fileName filename for the OCSP access certficate
   */
  public void setOCSPAccessCertificateFileName(String fileName) {
    this.setConfigurationParameter(ConfigurationParameter.OcspAccessCertificateFile, fileName);
    this.setDDoc4JParameter(Constant.DDoc4J.OCSP_PKCS_12_CONTAINER, fileName);
  }

  /**
   * Set OCSP access certificate password
   *
   * @param password password to set
   */
  public void setOCSPAccessCertificatePassword(char[] password) {
    String value = String.valueOf(password);
    this.setConfigurationParameter(ConfigurationParameter.OcspAccessCertificatePassword, value);
    this.setDDoc4JParameter(Constant.DDoc4J.OCSP_PKCS_12_PASSWORD, value);
  }

  /**
   * Set flag if OCSP requests should be signed
   *
   * @param shouldSignOcspRequests True if should sign, False otherwise
   */
  public void setSignOCSPRequests(boolean shouldSignOcspRequests) {
    String value = String.valueOf(shouldSignOcspRequests);
    this.setConfigurationParameter(ConfigurationParameter.SignOcspRequests, value);
    this.setDDoc4JParameter(Constant.DDoc4J.OCSP_SIGN_REQUESTS, value);
  }

  /**
   * Set a data loader factory that manages the creation of custom data loaders for creating OCSP requests.
   * @param ocspDataLoaderFactory OCSP data loader factory.
   */
  public void setOcspDataLoaderFactory(DataLoaderFactory ocspDataLoaderFactory) {
    this.ocspDataLoaderFactory = ocspDataLoaderFactory;
  }

  /**
   * Returns the currently set OCSP data loader factory or <code>null</code> if no custom data loader factory is set.
   * @return OCSP data loader factory.
   */
  public DataLoaderFactory getOcspDataLoaderFactory() {
    return ocspDataLoaderFactory;
  }

  /**
   * Add configuration settings from a stream. After loading closes stream.
   *
   * @param stream Input stream
   * @return configuration hashtable
   */
  public Hashtable<String, String> loadConfiguration(InputStream stream) {
    this.configurationInputSourceName = "stream";
    return this.loadConfigurationSettings(stream);
  }

  /**
   * Add configuration settings from a file
   *
   * @param file File name
   * @return configuration hashtable
   */
  public Hashtable<String, String> loadConfiguration(String file) {
    return this.loadConfiguration(file, true);
  }

  /**
   * Add configuration settings from a file
   *
   * @param file             File name
   * @param isReloadFromYaml True if this is reloading call
   * @return configuration hashtable
   */
  public Hashtable<String, String> loadConfiguration(String file, boolean isReloadFromYaml) {
    if (!isReloadFromYaml) {
      LOGGER.debug("Should not reload conf from yaml when open container");
      return ddoc4jConfiguration;
    }
    LOGGER.debug("Loading configuration from file <{}>", file);
    configurationInputSourceName = file;
    InputStream resourceAsStream = null;
    try {
      resourceAsStream = new FileInputStream(file);
    } catch (FileNotFoundException e) {
      LOGGER.debug("Configuration file <{}> not found. Trying to search from jar file", file);
    }
    if (resourceAsStream == null) {
      resourceAsStream = getResourceAsStream(file);
    }
    return loadConfigurationSettings(resourceAsStream);
  }

  /**
   * Returns configuration needed for DDoc4J library.
   *
   * @return configuration values.
   */
  public Hashtable<String, String> getDDoc4JConfiguration() {
    this.loadCertificateAuthoritiesAndCertificates();
    this.reportFileParseErrors();
    return ddoc4jConfiguration;
  }

  /**
   * Enables big files support. Sets limit in MB when handling files are creating temporary file for streaming in
   * container creation and adding data files.
   * <p/>
   * Used by DigiDoc4J and by DDoc4J.
   *
   * @param maxFileSizeCachedInMB Maximum size in MB.
   * @deprecated obnoxious naming. Use {@link Configuration#setMaxFileSizeCachedInMemoryInMB(long)} instead.
   */
  @Deprecated
  public void enableBigFilesSupport(long maxFileSizeCachedInMB) {
    LOGGER.debug("Set maximum datafile cached to: " + maxFileSizeCachedInMB);
    String value = Long.toString(maxFileSizeCachedInMB);
    if (isValidIntegerParameter("DIGIDOC_MAX_DATAFILE_CACHED", value)) {
      ddoc4jConfiguration.put("DIGIDOC_MAX_DATAFILE_CACHED", value);
    }
  }

  /**
   * Sets limit in MB when handling files are creating temporary file for streaming in
   * container creation and adding data files.
   * <p/>
   * Used by DigiDoc4J and by DDoc4J.
   *
   * @param maxFileSizeCachedInMB maximum data file size in MB stored in memory.
   */
  public void setMaxFileSizeCachedInMemoryInMB(long maxFileSizeCachedInMB) {
    enableBigFilesSupport(maxFileSizeCachedInMB);
  }

  /**
   * @return is big file support enabled
   * @deprecated obnoxious naming. Use {@link Configuration#storeDataFilesOnlyInMemory()} instead.
   */
  @Deprecated
  public boolean isBigFilesSupportEnabled() {
    return getMaxDataFileCachedInMB() >= 0;
  }

  /**
   * If all the data files should be stored in memory. Default is true (data files are temporarily stored only in
   * memory).
   *
   * @return true if everything is stored in memory, and false if data is temporarily stored on disk.
   */
  public boolean storeDataFilesOnlyInMemory() {
    long maxDataFileCachedInMB = getMaxDataFileCachedInMB();
    return maxDataFileCachedInMB == -1 || maxDataFileCachedInMB == Long.MAX_VALUE;
  }

  /**
   * Returns configuration item must be OCSP request signed. Reads it from registry parameter SIGN_OCSP_REQUESTS.
   * Default value is false for {@link Configuration.Mode#PROD} and false for {@link Configuration.Mode#TEST}
   *
   * @return must be OCSP request signed
   */
  public boolean hasToBeOCSPRequestSigned() {
    return Boolean.parseBoolean(this.getConfigurationParameter(ConfigurationParameter.SignOcspRequests));
  }

  /**
   * Get the maximum size of data files to be cached. Used by DigiDoc4J and by DDoc4J.
   *
   * @return Size in MB. if size < 0 no caching is used
   */
  public long getMaxDataFileCachedInMB() {
    String maxDataFileCached = ddoc4jConfiguration.get("DIGIDOC_MAX_DATAFILE_CACHED");
    LOGGER.debug("Maximum datafile cached in MB: " + maxDataFileCached);
    if (maxDataFileCached == null) return Constant.CACHE_ALL_DATA_FILES;
    return Long.parseLong(maxDataFileCached);
  }

  /**
   * Get the maximum size of data files to be cached. Used by DigiDoc4J and by DDoc4J.
   *
   * @return Size in MB. if size < 0 no caching is used
   */
  public long getMaxDataFileCachedInBytes() {
    long maxDataFileCachedInMB = getMaxDataFileCachedInMB();
    if (maxDataFileCachedInMB == Constant.CACHE_ALL_DATA_FILES) {
      return Constant.CACHE_ALL_DATA_FILES;
    } else {
      return (maxDataFileCachedInMB * Constant.ONE_MB_IN_BYTES);
    }
  }

  /**
   * Get TSL location.
   *
   * @return url
   */
  public String getTslLocation() {
    String urlString = getConfigurationParameter(ConfigurationParameter.TslLocation);
    if (!Protocol.isFileUrl(urlString)) return urlString;
    try {
      String filePath = new URL(urlString).getPath();
      if (!new File(filePath).exists()) {
        URL resource = getClass().getClassLoader().getResource(filePath);
        if (resource != null)
          urlString = resource.toString();
      }
    } catch (MalformedURLException e) {
      LOGGER.warn(e.getMessage());
    }
    return urlString == null ? "" : urlString;
  }

  /**
   * Set the TSL certificate source.
   *
   * @param certificateSource TSL certificate source
   *                          When certificateSource equals null then getTSL() will load the TSL according to the TSL
   *                          location specified .
   */

  public void setTSL(TSLCertificateSource certificateSource) {
    tslManager.setTsl(certificateSource);
  }

  /**
   * Loads TSL certificates
   * If configuration mode is TEST then TSL signature is not checked.
   *
   * @return TSL source
   */
  public TSLCertificateSource getTSL() {
    return tslManager.getTsl();
  }

  /**
   * Set the TSL location.
   * TSL can be loaded from file (file://) or from web (http://). If file protocol is used then
   * first try is to locate file from this location if file does not exist then it tries to load
   * relatively from classpath.
   * <p/>
   * Setting new location clears old values
   * <p/>
   * Windows wants it in file:DRIVE:/directories/tsl-file.xml format
   *
   * @param tslLocation TSL Location to be used
   */
  public void setTslLocation(String tslLocation) {
    this.setConfigurationParameter(ConfigurationParameter.TslLocation, tslLocation);
    this.tslManager.setTsl(null);
  }

  /**
   * Set a data loader factory that manages the creation of custom data loaders for downloading TSL.
   * @param tslDataLoaderFactory TSL data loader factory.
   */
  public void setTslDataLoaderFactory(DataLoaderFactory tslDataLoaderFactory) {
    this.tslDataLoaderFactory = tslDataLoaderFactory;
  }

  /**
   * Returns the currently set TSL data loader factory or <code>null</code> if no custom data loader factory is set.
   * @return TSL data loader factory.
   */
  public DataLoaderFactory getTslDataLoaderFactory() {
    return tslDataLoaderFactory;
  }

  /**
   * Set a data loader factory that manages the creation of custom data loaders for accessing AIA certificate sources.
   * @param aiaDataLoaderFactory AIA data loader factory.
   */
  public void setAiaDataLoaderFactory(DataLoaderFactory aiaDataLoaderFactory) {
    this.aiaDataLoaderFactory = aiaDataLoaderFactory;
  }

  /**
   * Returns the currently set AIA data loader factory or <code>null</code> if no custom data loader factory is set.
   * @return AIA data loader factory.
   */
  public DataLoaderFactory getAiaDataLoaderFactory() {
    return aiaDataLoaderFactory;
  }

  /**
   * Get the TSP Source
   *
   * @return TSP Source
   */
  public String getTspSource() {
    return this.getConfigurationParameter(ConfigurationParameter.TspSource);
  }

  /**
   * Get the TSP source by country
   *
   * @param country to use tsp source
   * @return tspSource
   */
  public String getTspSourceByCountry(String country) {
    if (this.tspMap.containsKey(country)) {
      String source = this.tspMap.get(country).get(ConfigurationParameter.TspCountrySource);
      if (StringUtils.isNotBlank(source)) {
        return source;
      }
    }
    LOGGER.info("Source by country <{}> not found, using default TSP source", country);
    return this.getTspSource();
  }

  /**
   * Set a data loader factory that manages the creation of custom data loaders for creating TSP requests.
   * @param tspDataLoaderFactory TSP data loader factory.
   */
  public void setTspDataLoaderFactory(DataLoaderFactory tspDataLoaderFactory) {
    this.tspDataLoaderFactory = tspDataLoaderFactory;
  }

  /**
   * Returns the currently set TSP data loader factory or <code>null</code> if no custom data loader factory is set.
   * @return TSP data loader factory.
   */
  public DataLoaderFactory getTspDataLoaderFactory() {
    return tspDataLoaderFactory;
  }

  /**
   * Set flag if AIA OCSP is preferred.
   *
   * @param preferAiaOcsp - True when AIA OCSP is preferred
   */
  public void setPreferAiaOcsp(boolean preferAiaOcsp) {
    this.setConfigurationParameter(ConfigurationParameter.preferAiaOcsp, String.valueOf(preferAiaOcsp));
  }

  /**
   * Get flag if AIA OCSP is preferred.
   *
   * @return isAiaOcspPreferred boolean value.
   */
  public boolean isAiaOcspPreferred() {
    return this.getConfigurationParameter(ConfigurationParameter.preferAiaOcsp, Boolean.class);
  }

  /**
   * Get the AIA OCSP source by issuer's CN
   *
   * @param cn to use AIA OCSP source
   * @return ocspSource
   */
  public String getAiaOcspSourceByCN(String cn) {
    if (this.aiaOcspMap.containsKey(cn)) {
      String source = this.aiaOcspMap.get(cn).get(ConfigurationParameter.aiaOcspSource);
      return source;
    }
    return null;
  }

  /**
   * Get the AIA OCSP source by issuer's CN
   *
   * @param cn to use AIA OCSP source
   * @return ocspSource
   */
  public boolean getUseNonceForAiaOcspByCN(String cn) {
    if (this.aiaOcspMap.containsKey(cn)) {
      String useNonce = this.aiaOcspMap.get(cn).get(ConfigurationParameter.useNonce);
      return Boolean.valueOf(useNonce);
    }
    return true;
  }

  /**
   * Set temp file max age in millis
   *
   * @param tempFileMaxAgeInMillis max age in millis
   */
  public void setTempFileMaxAge(long tempFileMaxAgeInMillis) {
    this.setConfigurationParameter(ConfigurationParameter.TempFileMaxAgeInMillis, String.valueOf(tempFileMaxAgeInMillis));
  }

  /**
   * Get temp file max age
   *
   * @return temp file max age in millis
   */
  public long getTempFileMaxAge() {
    return this.getConfigurationParameter(ConfigurationParameter.TempFileMaxAgeInMillis, Long.class);
  }

  /**
   * Set HTTP connection timeout
   *
   * @param connectionTimeout connection timeout in milliseconds
   */
  public void setConnectionTimeout(int connectionTimeout) {
    this.setConfigurationParameter(ConfigurationParameter.ConnectionTimeoutInMillis, String.valueOf(connectionTimeout));
  }

  /**
   * Set HTTP socket timeout
   *
   * @param socketTimeoutMilliseconds socket timeout in milliseconds
   */
  public void setSocketTimeout(int socketTimeoutMilliseconds) {
    this.setConfigurationParameter(ConfigurationParameter.SocketTimeoutInMillis,
        String.valueOf(socketTimeoutMilliseconds));
  }

  /**
   * Get HTTP connection timeout
   *
   * @return connection timeout in milliseconds
   */
  public int getConnectionTimeout() {
    return this.getConfigurationParameter(ConfigurationParameter.ConnectionTimeoutInMillis, Integer.class);
  }

  /**
   * Get HTTP socket timeout
   *
   * @return socket timeout in milliseconds
   */
  public int getSocketTimeout() {
    return this.getConfigurationParameter(ConfigurationParameter.SocketTimeoutInMillis, Integer.class);
  }

  /**
   * Set the TSP Source
   *
   * @param tspSource TSPSource to be used
   */
  public void setTspSource(String tspSource) {
    this.setConfigurationParameter(ConfigurationParameter.TspSource, tspSource);
  }

  /**
   * Get the OCSP Source
   *
   * @return OCSP Source
   */
  public String getOcspSource() {
    return this.getConfigurationParameter(ConfigurationParameter.OcspSource);
  }

  /**
   * Set if nonce should be used in case of OCSP request
   * <p/>
   * PS! Does not affect TM signature profiles in which occasion nonce is always used.
   *
   * @param useOcspNonce
   */
  public void setUseOcspNonce(Boolean useOcspNonce) {
    this.setConfigurationParameter(ConfigurationParameter.useNonce, useOcspNonce.toString());
  }

  /**
   * Get if OCSP nonce should be used
   *
   * @return use OCSP nonce
   */
  public boolean isOcspNonceUsed() {
    return this.getConfigurationParameter(ConfigurationParameter.useNonce, Boolean.class);
  }

  /**
   * Set the KeyStore Location that holds potential TSL Signing certificates
   *
   * @param tslKeyStoreLocation KeyStore location to use
   */
  public void setTslKeyStoreLocation(String tslKeyStoreLocation) {
    this.setConfigurationParameter(ConfigurationParameter.TslKeyStoreLocation, tslKeyStoreLocation);
  }

  /**
   * Get the Location to Keystore that holds potential TSL Signing certificates
   *
   * @return KeyStore Location
   */
  public String getTslKeyStoreLocation() {
    return this.getConfigurationParameter(ConfigurationParameter.TslKeyStoreLocation);
  }

  /**
   * Set the password for Keystore that holds potential TSL Signing certificates
   *
   * @param tslKeyStorePassword Keystore password
   */
  public void setTslKeyStorePassword(String tslKeyStorePassword) {
    this.setConfigurationParameter(ConfigurationParameter.TslKeyStorePassword, tslKeyStorePassword);
  }

  /**
   * Get the password for Keystore that holds potential TSL Signing certificates
   *
   * @return Tsl Keystore password
   */
  public String getTslKeyStorePassword() {
    return getConfigurationParameter(ConfigurationParameter.TslKeyStorePassword);
  }

  /**
   * Sets the expiration time for TSL cache in milliseconds.
   * If more time has passed from the cache's creation time time, then a fresh TSL is downloaded and cached,
   * otherwise a cached copy is used.
   *
   * @param cacheExpirationTimeInMilliseconds cache expiration time in milliseconds
   */
  public void setTslCacheExpirationTime(long cacheExpirationTimeInMilliseconds) {
    this.setConfigurationParameter(ConfigurationParameter.TslCacheExpirationTimeInMillis,
        String.valueOf(cacheExpirationTimeInMilliseconds));
  }

  /**
   * Returns TSL cache expiration time in milliseconds.
   *
   * @return TSL cache expiration time in milliseconds.
   */
  public long getTslCacheExpirationTime() {
    return this.getConfigurationParameter(ConfigurationParameter.TslCacheExpirationTimeInMillis, Long.class);
  }

  /**
   * Returns allowed delay between timestamp and OCSP response in minutes.
   *
   * @return Allowed delay between timestamp and OCSP response in minutes.
   */
  public Integer getAllowedTimestampAndOCSPResponseDeltaInMinutes() {
    return this.getConfigurationParameter(ConfigurationParameter.AllowedTimestampAndOCSPResponseDeltaInMinutes,
        Integer.class);
  }

  /**
   * Set allowed delay between timestamp and OCSP response in minutes.
   *
   * @param timeInMinutes Allowed delay between timestamp and OCSP response in minutes
   */
  public void setAllowedTimestampAndOCSPResponseDeltaInMinutes(int timeInMinutes) {
    this.setConfigurationParameter(ConfigurationParameter.AllowedTimestampAndOCSPResponseDeltaInMinutes,
        String.valueOf(timeInMinutes));
  }

  /**
   * Set the OCSP source
   *
   * @param ocspSource OCSP Source to be used
   */
  public void setOcspSource(String ocspSource) {
    this.setConfigurationParameter(ConfigurationParameter.OcspSource, ocspSource);
  }

  /**
   * Get the validation policy
   *
   * @return Validation policy
   */
  public String getValidationPolicy() {
    return this.getConfigurationParameter(ConfigurationParameter.ValidationPolicy);
  }

  /**
   * Set the validation policy
   *
   * @param validationPolicy Policy to be used
   */
  public void setValidationPolicy(String validationPolicy) {
    this.setConfigurationParameter(ConfigurationParameter.ValidationPolicy, validationPolicy);
  }

  /**
   * @return whether to print validation report
   */
  public boolean getPrintValidationReport() {
    return this.getConfigurationParameter(ConfigurationParameter.PrintValidationReport, Boolean.class);
  }

  /**
   * @param printValidationReport whether to print validation report
   */
  public void setPrintValidationReport(Boolean printValidationReport) {
    this.setConfigurationParameter(ConfigurationParameter.PrintValidationReport, printValidationReport.toString());
  }

  /**
   * Revocation and timestamp delta in minutes.
   *
   * @return timestamp delta in minutes.
   */
  public int getRevocationAndTimestampDeltaInMinutes() {
    return this.getConfigurationParameter(ConfigurationParameter.RevocationAndTimestampDeltaInMinutes, Integer.class);
  }

  /**
   * Set Revocation and timestamp delta in minutes.
   *
   * @param timeInMinutes delta in minutes.
   */
  public void setRevocationAndTimestampDeltaInMinutes(int timeInMinutes) {
    this.setConfigurationParameter(ConfigurationParameter.RevocationAndTimestampDeltaInMinutes,
        String.valueOf(timeInMinutes));
  }

  /**
   * Signature profile.
   *
   * @return SignatureProfile.
   */
  public SignatureProfile getSignatureProfile() {
    return SignatureProfile.findByProfile(this.getConfigurationParameter(ConfigurationParameter.SignatureProfile));
  }

  /**
   * Signature digest algorithm.
   *
   * @return DigestAlgorithm.
   */
  public DigestAlgorithm getSignatureDigestAlgorithm() {
    return DigestAlgorithm.findByAlgorithm(getConfigurationParameter(ConfigurationParameter.SignatureDigestAlgorithm));
  }

  /**
   * @return HTTPS proxy host
   */
  public String getHttpsProxyHost() {
    return this.getConfigurationParameter(ConfigurationParameter.HttpsProxyHost);
  }

  /**
   * @param connectionType type of external connections.
   * @return HTTPS proxy host.
   */
  public String getHttpsProxyHostFor(ExternalConnectionType connectionType) {
    String proxyHost = this.getConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpsProxyHost));
    return (proxyHost != null) ? proxyHost : this.getHttpsProxyHost();
  }

  /**
   * Set HTTPS network proxy host.
   *
   * @param httpsProxyHost https proxy host.
   */
  public void setHttpsProxyHost(String httpsProxyHost) {
    this.setConfigurationParameter(ConfigurationParameter.HttpsProxyHost, httpsProxyHost);
  }

  /**
   * Set HTTPS network proxy host for specific type of external connections.
   * Overrides network proxy host set via {@link Configuration#setHttpsProxyHost(String)}
   *
   * @param connectionType type of external connections.
   * @param httpsProxyHost https proxy host.
   */
  public void setHttpsProxyHostFor(ExternalConnectionType connectionType, String httpsProxyHost) {
    this.setConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpsProxyHost), httpsProxyHost);
  }

  /**
   * @return HTTPS proxy port
   */
  public Integer getHttpsProxyPort() {
    return this.getConfigurationParameter(ConfigurationParameter.HttpsProxyPort, Integer.class);
  }

  /**
   * @param connectionType type of external connection
   * @return HTTPS proxy port
   */
  public Integer getHttpsProxyPortFor(ExternalConnectionType connectionType) {
    Integer proxyPort = this.getConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpsProxyPort), Integer.class);
    return (proxyPort != null) ? proxyPort : this.getHttpsProxyPort();
  }

  /**
   * Set HTTPS network proxy port.
   *
   * @param httpsProxyPort https proxy port.
   */
  public void setHttpsProxyPort(int httpsProxyPort) {
    this.setConfigurationParameter(ConfigurationParameter.HttpsProxyPort, String.valueOf(httpsProxyPort));
  }

  /**
   * Set HTTPS network proxy port for specific type of external connections.
   * Overrides network proxy port set via {@link Configuration#setHttpsProxyPort(int)}
   *
   * @param connectionType type of external connections.
   * @param httpsProxyPort https proxy port.
   */
  public void setHttpsProxyPortFor(ExternalConnectionType connectionType, int httpsProxyPort) {
    this.setConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpsProxyPort), String.valueOf(httpsProxyPort));
  }


  /**
   * Get http proxy host.
   *
   * @return http proxy host.
   */
  public String getHttpProxyHost() {
    return this.getConfigurationParameter(ConfigurationParameter.HttpProxyHost);
  }

  /**
   * Get http proxy host for specific external connection type.
   *
   * @param connectionType type of external connections.
   * @return http proxy host.
   */
  public String getHttpProxyHostFor(ExternalConnectionType connectionType) {
    String proxyHost = this.getConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpProxyHost));
    return (proxyHost != null) ? proxyHost : this.getHttpProxyHost();
  }

  /**
   * Set HTTP network proxy host.
   *
   * @param httpProxyHost http proxy host.
   */
  public void setHttpProxyHost(String httpProxyHost) {
    this.setConfigurationParameter(ConfigurationParameter.HttpProxyHost, httpProxyHost);
  }

  /**
   * Set HTTP network proxy host for specific type of external connections.
   * Overrides network proxy host set via {@link Configuration#setHttpProxyHost(String)}
   *
   * @param connectionType type of external connections.
   * @param httpProxyHost http proxy host.
   */
  public void setHttpProxyHostFor(ExternalConnectionType connectionType, String httpProxyHost) {
    this.setConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpProxyHost), httpProxyHost);
  }

  /**
   * Get http proxy port.
   *
   * @return http proxy port.
   */
  public Integer getHttpProxyPort() {
    return this.getConfigurationParameter(ConfigurationParameter.HttpProxyPort, Integer.class);
  }

  /**
   * Get http proxy port for specific type of external connections.
   *
   * @param connectionType type of external connections.
   * @return http proxy port.
   */
  public Integer getHttpProxyPortFor(ExternalConnectionType connectionType) {
    Integer proxyPort = this.getConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpProxyPort), Integer.class);
    return (proxyPort != null) ? proxyPort : this.getHttpProxyPort();
  }

  /**
   * Set HTTP network proxy port.
   *
   * @param httpProxyPort Port number.
   */
  public void setHttpProxyPort(int httpProxyPort) {
    this.setConfigurationParameter(ConfigurationParameter.HttpProxyPort, String.valueOf(httpProxyPort));
  }

  /**
   * Set HTTP network proxy port for specific type of external connections.
   * Overrides network proxy port set via {@link Configuration#setHttpProxyPort(int)}
   *
   * @param connectionType type of external connections.
   * @param httpProxyPort Port number.
   */
  public void setHttpProxyPortFor(ExternalConnectionType connectionType, int httpProxyPort) {
    this.setConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpProxyPort), String.valueOf(httpProxyPort));
  }

  /**
   * Set HTTP network proxy user name.
   *
   * @param httpProxyUser username.
   */
  public void setHttpProxyUser(String httpProxyUser) {
    this.setConfigurationParameter(ConfigurationParameter.HttpProxyUser, httpProxyUser);
  }

  /**
   * Set HTTP network proxy user name for specific type of external connections.
   * Overrides network proxy user name set via {@link Configuration#setHttpProxyUser(String)}
   *
   * @param connectionType type of external connections.
   * @param httpProxyUser username.
   */
  public void setHttpProxyUserFor(ExternalConnectionType connectionType, String httpProxyUser) {
    this.setConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpProxyUser), httpProxyUser);
  }

  /**
   * Get http proxy user.
   *
   * @return http proxy user.
   */
  public String getHttpProxyUser() {
    return this.getConfigurationParameter(ConfigurationParameter.HttpProxyUser);
  }

  /**
   * Get http proxy user for specific type of external connections.
   *
   * @param connectionType type of external connections.
   * @return http proxy user.
   */
  public String getHttpProxyUserFor(ExternalConnectionType connectionType) {
    String proxyUser = this.getConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpProxyUser));
    return (proxyUser != null) ? proxyUser : this.getHttpProxyUser();
  }

  /**
   * Set HTTP network proxy password.
   *
   * @param httpProxyPassword password.
   */
  public void setHttpProxyPassword(String httpProxyPassword) {
    this.setConfigurationParameter(ConfigurationParameter.HttpProxyPassword, httpProxyPassword);
  }

  /**
   * Set HTTP network proxy password for specific type of external connections.
   * Overrides network proxy password set via {@link Configuration#setHttpProxyPassword(String)}
   *
   * @param connectionType type of external connections.
   * @param httpProxyPassword password.
   */
  public void setHttpProxyPasswordFor(ExternalConnectionType connectionType, String httpProxyPassword) {
    this.setConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpProxyPassword), httpProxyPassword);
  }

  /**
   * Get http proxy password.
   *
   * @return http proxy password.
   */
  public String getHttpProxyPassword() {
    return this.getConfigurationParameter(ConfigurationParameter.HttpProxyPassword);
  }

  /**
   * Get http proxy password for specific type of external connections.
   *
   * @param connectionType type of external connections.
   * @return http proxy password.
   */
  public String getHttpProxyPasswordFor(ExternalConnectionType connectionType) {
    String proxyPassword = this.getConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpProxyPassword));
    return (proxyPassword != null) ? proxyPassword : this.getHttpProxyPassword();
  }

  /**
   * Is network proxy enabled?
   *
   * @return True if network proxy is enabled, otherwise False.
   */
  public boolean isNetworkProxyEnabled() {
    return this.getHttpProxyPort() != null && StringUtils.isNotBlank(this.getHttpProxyHost()) ||
            this.getHttpsProxyPort() != null && StringUtils.isNotBlank(this.getHttpsProxyHost());
  }

  /**
   * Is network proxy enabled for specific type of external connections?
   *
   * @param connectionType type of external connections.
   * @return True if network proxy is enabled, otherwise False.
   */
  public boolean isNetworkProxyEnabledFor(ExternalConnectionType connectionType) {
    return this.getHttpProxyPortFor(connectionType) != null && StringUtils.isNotBlank(this.getHttpProxyHostFor(connectionType)) ||
            this.getHttpsProxyPortFor(connectionType) != null && StringUtils.isNotBlank(this.getHttpsProxyHostFor(connectionType));
  }

  /**
   * @param protocol protocol
   * @return boolean
   */
  public boolean isProxyOfType(Protocol protocol) {
    switch (protocol) {
      case HTTP:
        return this.getHttpProxyPort() != null && StringUtils.isNotBlank(this.getHttpProxyHost());
      case HTTPS:
        return this.getHttpsProxyPort() != null && StringUtils.isNotBlank(this.getHttpsProxyHost());
      default:
        throw new RuntimeException(String.format("Protocol <%s> not supported", protocol));
    }
  }

  /**
   * @param connectionType type of external connections
   * @param protocol protocol
   * @return boolean
   */
  public boolean isProxyOfTypeFor(ExternalConnectionType connectionType, Protocol protocol) {
    switch (protocol) {
      case HTTP:
        return this.getHttpProxyPortFor(connectionType) != null && StringUtils.isNotBlank(this.getHttpProxyHostFor(connectionType));
      case HTTPS:
        return this.getHttpsProxyPortFor(connectionType) != null && StringUtils.isNotBlank(this.getHttpsProxyHostFor(connectionType));
      default:
        throw new RuntimeException(String.format("Protocol <%s> not supported", protocol));
    }
  }

  /**
   * Is ssl configuration enabled?
   *
   * @return True if SSL configuration is enabled, otherwise False.
   */
  public boolean isSslConfigurationEnabled() {
    return StringUtils.isNotBlank(this.getSslKeystorePath()) ||
        StringUtils.isNotBlank(this.getSslTruststorePath()) ||
        StringUtils.isNotBlank(this.getSslProtocol()) ||
        CollectionUtils.isNotEmpty(this.getSupportedSslProtocols()) ||
        CollectionUtils.isNotEmpty(this.getSupportedSslCipherSuites());
  }

  /**
   * Is ssl configuration enabled for specific type of external connections?
   *
   * @param connectionType type of external connections.
   * @return True if SSL configuration is enabled, otherwise False.
   */
  public boolean isSslConfigurationEnabledFor(ExternalConnectionType connectionType) {
    return StringUtils.isNotBlank(this.getSslKeystorePathFor(connectionType)) ||
        StringUtils.isNotBlank(this.getSslTruststorePathFor(connectionType)) ||
        StringUtils.isNotBlank(this.getSslProtocolFor(connectionType)) ||
        CollectionUtils.isNotEmpty(this.getSupportedSslProtocolsFor(connectionType)) ||
        CollectionUtils.isNotEmpty(this.getSupportedSslCipherSuitesFor(connectionType));
  }

  /**
   * Set SSL KeyStore path.
   *
   * @param sslKeystorePath path to SSL keystore.
   */
  public void setSslKeystorePath(String sslKeystorePath) {
    this.setConfigurationParameter(ConfigurationParameter.SslKeystorePath, sslKeystorePath);
  }

  /**
   * Set SSL KeyStore path for specific type of external connections.
   * Overrides keystore path set via {@link Configuration#setSslKeystorePath(String)}
   *
   * @param connectionType type of external connections.
   * @param sslKeystorePath path to SSL keystore.
   */
  public void setSslKeystorePathFor(ExternalConnectionType connectionType, String sslKeystorePath) {
    this.setConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.SslKeystorePath), sslKeystorePath);
  }

  /**
   * Get SSL KeyStore path.
   *
   * @return path to SSL keystore.
   */
  public String getSslKeystorePath() {
    return this.getConfigurationParameter(ConfigurationParameter.SslKeystorePath);
  }

  /**
   * Get SSL KeyStore path for specific type of external connections.
   *
   * @param connectionType type of external connections.
   * @return path to SSL keystore.
   */
  public String getSslKeystorePathFor(ExternalConnectionType connectionType) {
    String keystorePath = this.getConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.SslKeystorePath));
    return (keystorePath != null) ? keystorePath : this.getSslKeystorePath();
  }

  /**
   * Set SSL KeyStore type. Default is "jks".
   *
   * @param sslKeystoreType type of SSL keystore.
   */
  public void setSslKeystoreType(String sslKeystoreType) {
    this.setConfigurationParameter(ConfigurationParameter.SslKeystoreType, sslKeystoreType);
  }

  /**
   * Set SSL KeyStore type for specific type of external connections.
   * Overrides keystore type set via {@link Configuration#setSslKeystoreType(String)}
   *
   * @param connectionType type of external connections.
   * @param sslKeystoreType type of SSL keystore.
   */
  public void setSslKeystoreTypeFor(ExternalConnectionType connectionType, String sslKeystoreType) {
    this.setConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.SslKeystoreType), sslKeystoreType);
  }

  /**
   * Get SSL KeyStore type.
   *
   * @return type of SSL keystore.
   */
  public String getSslKeystoreType() {
    return this.getConfigurationParameter(ConfigurationParameter.SslKeystoreType);
  }

  /**
   * Get SSL KeyStore type for specific type of external connections.
   *
   * @param connectionType type of external connections.
   * @return type of SSL keystore.
   */
  public String getSslKeystoreTypeFor(ExternalConnectionType connectionType) {
    String keystoreType = this.getConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.SslKeystoreType));
    return (keystoreType != null) ? keystoreType : this.getSslKeystoreType();
  }

  /**
   * Set SSL KeyStore password. Default is an empty string.
   *
   * @param sslKeystorePassword SSL keystore password.
   */
  public void setSslKeystorePassword(String sslKeystorePassword) {
    this.setConfigurationParameter(ConfigurationParameter.SslKeystorePassword, sslKeystorePassword);
  }

  /**
   * Set SSL KeyStore password for specific type of external connections.
   * Overrides keystore password set via {@link Configuration#setSslKeystorePassword(String)}
   *
   * @param connectionType type of external connections.
   * @param sslKeystorePassword SSL keystore password.
   */
  public void setSslKeystorePasswordFor(ExternalConnectionType connectionType, String sslKeystorePassword) {
    this.setConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.SslKeystorePassword), sslKeystorePassword);
  }

  /**
   * Get Ssl keystore password.
   *
   * @return SSL keystore password.
   */
  public String getSslKeystorePassword() {
    return this.getConfigurationParameter(ConfigurationParameter.SslKeystorePassword);
  }

  /**
   * Get Ssl keystore password for specific type of external connections.
   *
   * @param connectionType type of external connections.
   * @return SSL keystore password.
   */
  public String getSslKeystorePasswordFor(ExternalConnectionType connectionType) {
    String keystorePassword = this.getConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.SslKeystorePassword));
    return (keystorePassword != null) ? keystorePassword : this.getSslKeystorePassword();
  }

  /**
   * Set SSL TrustStore path.
   *
   * @param sslTruststorePath path to SSL truststore.
   */
  public void setSslTruststorePath(String sslTruststorePath) {
    this.setConfigurationParameter(ConfigurationParameter.SslTruststorePath, sslTruststorePath);
  }

  /**
   * Set SSL TrustStore path for specific type of external connections.
   * Overrides truststore path set via {@link Configuration#setSslTruststorePath(String)}
   *
   * @param connectionType type of external connections.
   * @param sslTruststorePath path to SSL truststore.
   */
  public void setSslTruststorePathFor(ExternalConnectionType connectionType, String sslTruststorePath) {
    this.setConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.SslTruststorePath), sslTruststorePath);
  }

  /**
   * Get SSL TrustStore path
   *
   * @return path to SSL truststore.
   */
  public String getSslTruststorePath() {
    return this.getConfigurationParameter(ConfigurationParameter.SslTruststorePath);
  }

  /**
   * Get SSL TrustStore path for specific type of external connections.
   *
   * @param connectionType type of external connections.
   * @return path to SSL truststore.
   */
  public String getSslTruststorePathFor(ExternalConnectionType connectionType) {
    String truststorePath = this.getConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.SslTruststorePath));
    return (truststorePath != null) ? truststorePath : this.getSslTruststorePath();
  }

  /**
   * Set SSL TrustStore type. Default is "jks".
   *
   * @param sslTruststoreType type of SSL truststore.
   */
  public void setSslTruststoreType(String sslTruststoreType) {
    this.setConfigurationParameter(ConfigurationParameter.SslTruststoreType, sslTruststoreType);
  }

  /**
   * Set SSL TrustStore type for specific type of external connections.
   * Overrides truststore type set via {@link Configuration#setSslTruststoreType(String)}
   *
   * @param connectionType type of external connections.
   * @param sslTruststoreType type of SSL truststore.
   */
  public void setSslTruststoreTypeFor(ExternalConnectionType connectionType, String sslTruststoreType) {
    this.setConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.SslTruststoreType), sslTruststoreType);
  }

  /**
   * Get SSL TrustStore type.
   *
   * @return type of SSL truststore.
   */
  public String getSslTruststoreType() {
    return this.getConfigurationParameter(ConfigurationParameter.SslTruststoreType);
  }

  /**
   * Get SSL TrustStore type for specific type of external connections.
   *
   * @param connectionType type of external connections.
   * @return type of SSL truststore.
   */
  public String getSslTruststoreTypeFor(ExternalConnectionType connectionType) {
    String truststoreType = this.getConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.SslTruststoreType));
    return (truststoreType != null) ? truststoreType : this.getSslTruststoreType();
  }

  /**
   * Set SSL TrustStore password. Default is an empty string.
   *
   * @param sslTruststorePassword SSL truststore password.
   */
  public void setSslTruststorePassword(String sslTruststorePassword) {
    this.setConfigurationParameter(ConfigurationParameter.SslTruststorePassword, sslTruststorePassword);
  }

  /**
   * Set SSL TrustStore password for specific type of external connections.
   * Overrides truststore password set via {@link Configuration#setSslTruststorePassword(String)}
   *
   * @param connectionType type of external connections.
   * @param sslTruststorePassword SSL truststore password.
   */
  public void setSslTruststorePasswordFor(ExternalConnectionType connectionType, String sslTruststorePassword) {
    this.setConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.SslTruststorePassword), sslTruststorePassword);
  }

  /**
   * Get Ssl truststore password.
   *
   * @return SSL truststore password.
   */
  public String getSslTruststorePassword() {
    return this.getConfigurationParameter(ConfigurationParameter.SslTruststorePassword);
  }

  /**
   * Get Ssl truststore password for specific type of external connections.
   *
   * @param connectionType type of external connections.
   * @return SSL truststore password.
   */
  public String getSslTruststorePasswordFor(ExternalConnectionType connectionType) {
    String truststorePassword = this.getConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.SslTruststorePassword));
    return (truststorePassword != null) ? truststorePassword : this.getSslTruststorePassword();
  }

  /**
   * Set SSL protocol.
   *
   * @param sslProtocol SSL protocol.
   */
  public void setSslProtocol(String sslProtocol) {
    this.setConfigurationParameter(ConfigurationParameter.SslProtocol, sslProtocol);
  }

  /**
   * Set SSL protocol for specific type of external connections.
   * Overrides SSL protocol set via {@link Configuration#setSslProtocol(String)}
   *
   * @param connectionType type of external connections.
   * @param sslProtocol SSL protocol.
   */
  public void setSslProtocolFor(ExternalConnectionType connectionType, String sslProtocol) {
    this.setConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.SslProtocol), sslProtocol);
  }

  /**
   * Get SSL protocol.
   *
   * @return SSL protocol.
   */
  public String getSslProtocol() {
    return this.getConfigurationParameter(ConfigurationParameter.SslProtocol);
  }

  /**
   * Get SSL protocol for specific type of external connections.
   *
   * @param connectionType type of external connections.
   * @return SSL protocol.
   */
  public String getSslProtocolFor(ExternalConnectionType connectionType) {
    String protocol = this.getConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.SslProtocol));
    return (protocol != null) ? protocol : this.getSslProtocol();
  }

  /**
   * Set supported SSL protocols.
   *
   * @param supportedSslProtocols list of supported SSL protocols.
   */
  public void setSupportedSslProtocols(List<String> supportedSslProtocols) {
    this.setConfigurationParameter(ConfigurationParameter.SupportedSslProtocols, Optional.ofNullable(supportedSslProtocols)
        .map(l -> l.toArray(new String[l.size()])).orElse(null));
  }

  /**
   * Set supported SSL protocols for specific type of external connections.
   * Overrides SSL protocols set via {@link Configuration#setSupportedSslProtocols(List)}
   *
   * @param connectionType type of external connections.
   * @param supportedSslProtocols list of supported SSL protocols.
   */
  public void setSupportedSslProtocolsFor(ExternalConnectionType connectionType, List<String> supportedSslProtocols) {
    this.setConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.SupportedSslProtocols),
        Optional.ofNullable(supportedSslProtocols).map(l -> l.toArray(new String[l.size()])).orElse(null));
  }

  /**
   * Get supported SSL protocols.
   *
   * @return list of supported SSL protocols.
   */
  public List<String> getSupportedSslProtocols() {
    return this.getConfigurationValues(ConfigurationParameter.SupportedSslProtocols);
  }

  /**
   * Get supported SSL protocols for specific type of external connections.
   *
   * @param connectionType type of external connections.
   * @return list of supported SSL protocols.
   */
  public List<String> getSupportedSslProtocolsFor(ExternalConnectionType connectionType) {
    List<String> supportedProtocols = this.getConfigurationValues(connectionType.mapToSpecificParameter(ConfigurationParameter.SupportedSslProtocols));
    return (supportedProtocols != null) ? supportedProtocols : this.getSupportedSslProtocols();
  }

  /**
   * Set supported SSL cipher suites.
   *
   * @param supportedSslCipherSuites list of supported SSL cipher suites.
   */
  public void setSupportedSslCipherSuites(List<String> supportedSslCipherSuites) {
    this.setConfigurationParameter(ConfigurationParameter.SupportedSslCipherSuites, Optional.ofNullable(supportedSslCipherSuites)
            .map(l -> l.toArray(new String[l.size()])).orElse(null));
  }

  /**
   * Set supported SSL cipher suites for specific type of external connections.
   * Overrides SSL cipher suites set via {@link Configuration#setSupportedSslCipherSuites(List)}
   *
   * @param connectionType type of external connections.
   * @param supportedSslCipherSuites list of supported SSL cipher suites.
   */
  public void setSupportedSslCipherSuitesFor(ExternalConnectionType connectionType, List<String> supportedSslCipherSuites) {
    this.setConfigurationParameter(connectionType.mapToSpecificParameter(ConfigurationParameter.SupportedSslCipherSuites),
        Optional.ofNullable(supportedSslCipherSuites).map(l -> l.toArray(new String[l.size()])).orElse(null));
  }

  /**
   * Get supported SSL cipher suites.
   *
   * @return list of supported SSL cipher suites.
   */
  public List<String> getSupportedSslCipherSuites() {
    return this.getConfigurationValues(ConfigurationParameter.SupportedSslCipherSuites);
  }

  /**
   * Get supported SSL cipher suites for specific type of external connections.
   *
   * @param connectionType type of external connections.
   * @return list of supported SSL cipher suites.
   */
  public List<String> getSupportedSslCipherSuitesFor(ExternalConnectionType connectionType) {
    List<String> supportedCipherSuites = this.getConfigurationValues(connectionType.mapToSpecificParameter(ConfigurationParameter.SupportedSslCipherSuites));
    return (supportedCipherSuites != null) ? supportedCipherSuites : this.getSupportedSslCipherSuites();
  }

  /**
   * Set flag if full report needed.
   *
   * @param isFullReport needed value.
   */
  public void setFullReportNeeded(boolean isFullReport) {
    this.setConfigurationParameter(ConfigurationParameter.IsFullSimpleReportNeeded, String.valueOf(isFullReport));
  }

  /**
   * Get flag if full report needed.
   *
   * @return isFullReport needed boolean value.
   */
  public boolean isFullReportNeeded() {
    return Boolean.parseBoolean(this.getConfigurationParameter(ConfigurationParameter.IsFullSimpleReportNeeded));
  }

  /**
   * Set flag if ASN1 Unsafe Integer is Allowed.
   *
   * @param isAllowed - True when ASN1 Unsafe Integer is Allowed.
   */
  public void setAllowASN1UnsafeInteger(boolean isAllowed) {
    this.setConfigurationParameter(ConfigurationParameter.AllowASN1UnsafeInteger, String.valueOf(isAllowed));
    this.postLoad();
  }

  /**
   * Get flag if ASN1 Unsafe Integer is Allowed.
   *
   * @return isASN1UnsafeIntegerAllowed boolean value.
   */
  public boolean isASN1UnsafeIntegerAllowed() {
    return Boolean.parseBoolean(this.getConfigurationParameter(ConfigurationParameter.AllowASN1UnsafeInteger));
  }

  /**
   * Set thread executor service.
   *
   * @param threadExecutor Thread executor service object.
   */
  public void setThreadExecutor(ExecutorService threadExecutor) {
    this.threadExecutor = threadExecutor;
  }

  /**
   * Get thread executor. It can be mull.
   *
   * @return thread executor.
   */
  public ExecutorService getThreadExecutor() {
    return threadExecutor;
  }

  /**
   * Set countries and territories (2 letter country codes) whom to trust and accept certificates.
   * <p/>
   * It is possible accept signatures (and certificates) only from particular countries by filtering
   * trusted territories. Only the TSL (and certificates) from those countries are then downloaded and
   * others are skipped.
   * <p/>
   * For example, it is possible to trust signatures only from these three countries: Estonia, Latvia and France,
   * and skip all other countries: "EE", "LV", "FR".
   *
   * @param trustedTerritories list of 2 letter country codes.
   */
  public void setTrustedTerritories(String... trustedTerritories) {
    this.trustedTerritories = Arrays.asList(trustedTerritories);
  }

  /**
   * Get trusted territories.
   *
   * @return trusted territories list.
   */
  public List<String> getTrustedTerritories() {
    return trustedTerritories;
  }

  /**
   * Set allowed OCSP responders common names for timemark validation.
   * For example: "SK OCSP RESPONDER 2011", "ESTEID-SK OCSP RESPONDER", "KLASS3-SK OCSP RESPONDER".
   *
   * @param allowedOcspRespondersForTM list of OCSP responders.
   */
  public void setAllowedOcspRespondersForTM(String... allowedOcspRespondersForTM) {
    this.setConfigurationParameter(ConfigurationParameter.AllowedOcspRespondersForTM, allowedOcspRespondersForTM);
    setDDoc4JParameter("ALLOWED_OCSP_RESPONDERS_FOR_TM", StringUtils.join(allowedOcspRespondersForTM, ","));
  }

  /**
   * Get allowed OCSP responders for timemark validation.
   *
   * @return ocsp responders list.
   */
  public List<String> getAllowedOcspRespondersForTM() {
    return this.getConfigurationValues(ConfigurationParameter.AllowedOcspRespondersForTM);
  }

  /**
   * @return true when configuration is Configuration.Mode.TEST
   * @see Configuration.Mode#TEST
   */
  public boolean isTest() {
    boolean isTest = Mode.TEST.equals(this.mode);
    LOGGER.debug("Is test: " + isTest);
    return isTest;
  }

  /**
   * Clones configuration
   *
   * @return new configuration object
   */
  public Configuration copy() {
    ObjectOutputStream oos = null;
    ObjectInputStream ois = null;
    Configuration copyConfiguration = null;
    // deep copy
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try {
      oos = new ObjectOutputStream(bos);
      oos.writeObject(this);
      oos.flush();
      ByteArrayInputStream bin =
          new ByteArrayInputStream(bos.toByteArray());
      ois = new ObjectInputStream(bin);
      copyConfiguration = (Configuration) ois.readObject();
    } catch (Exception e) {
      throw new DigiDoc4JException(e);
    } finally {
      IOUtils.closeQuietly(oos);
      IOUtils.closeQuietly(ois);
      IOUtils.closeQuietly(bos);
    }
    return copyConfiguration;
  }

  /*
   * RESTRICTED METHODS
   */

  protected ConfigurationRegistry getRegistry() {
    return this.registry;
  }

  private void initDefaultValues() {
    LOGGER.debug("------------------------ DEFAULTS ------------------------");
    this.tslManager = new TslManager(this);
    this.setConfigurationParameter(ConfigurationParameter.ConnectionTimeoutInMillis,
        String.valueOf(Constant.ONE_SECOND_IN_MILLISECONDS));
    this.setConfigurationParameter(ConfigurationParameter.SocketTimeoutInMillis,
        String.valueOf(Constant.ONE_SECOND_IN_MILLISECONDS));
    this.setConfigurationParameter(ConfigurationParameter.TslKeyStorePassword, "digidoc4j-password");
    this.setConfigurationParameter(ConfigurationParameter.RevocationAndTimestampDeltaInMinutes,
        String.valueOf(Constant.ONE_DAY_IN_MINUTES));
    this.setConfigurationParameter(ConfigurationParameter.TslCacheExpirationTimeInMillis,
        String.valueOf(Constant.ONE_DAY_IN_MILLISECONDS));
    this.setConfigurationParameter(ConfigurationParameter.TempFileMaxAgeInMillis,
        String.valueOf(Constant.ONE_DAY_IN_MILLISECONDS));
    this.setConfigurationParameter(ConfigurationParameter.AllowedTimestampAndOCSPResponseDeltaInMinutes, "15");
    this.setConfigurationParameter(ConfigurationParameter.SignatureProfile, Constant.Default.SIGNATURE_PROFILE);
    this.setConfigurationParameter(ConfigurationParameter.SignatureDigestAlgorithm,
        Constant.Default.SIGNATURE_DIGEST_ALGORITHM);
    this.setConfigurationParameter(ConfigurationParameter.IsFullSimpleReportNeeded,
        Constant.Default.FULL_SIMPLE_REPORT);
    this.setConfigurationParameter(ConfigurationParameter.useNonce, "true");
    if (Mode.TEST.equals(this.mode)) {
      this.setConfigurationParameter(ConfigurationParameter.TspSource, Constant.Test.TSP_SOURCE);
      this.setConfigurationParameter(ConfigurationParameter.TslLocation, Constant.Test.TSL_LOCATION);
      this.setConfigurationParameter(ConfigurationParameter.TslKeyStoreLocation, Constant.Test.TSL_KEYSTORE_LOCATION);
      this.setConfigurationParameter(ConfigurationParameter.ValidationPolicy, Constant.Test.VALIDATION_POLICY);
      this.setConfigurationParameter(ConfigurationParameter.OcspSource, Constant.Test.OCSP_SOURCE);
      this.setConfigurationParameter(ConfigurationParameter.SignOcspRequests, "false");
      this.setConfigurationParameter(ConfigurationParameter.PrintValidationReport, "true");
      this.setDDoc4JParameter("SIGN_OCSP_REQUESTS", "false");
      setDDoc4JParameter("ALLOWED_OCSP_RESPONDERS_FOR_TM", StringUtils.join(Constant.Test.DEFAULT_OCSP_RESPONDERS, ","));
      this.setConfigurationParameter(ConfigurationParameter.AllowedOcspRespondersForTM, Constant.Test.DEFAULT_OCSP_RESPONDERS);
      this.setConfigurationParameter(ConfigurationParameter.preferAiaOcsp, "false");
      this.loadYamlAiaOCSPs(loadYamlFromResource("defaults/demo_aia_ocsp.yaml"), true);
    } else {
      this.setConfigurationParameter(ConfigurationParameter.TspSource, Constant.Production.TSP_SOURCE);
      this.setConfigurationParameter(ConfigurationParameter.TslLocation, Constant.Production.TSL_LOCATION);
      this.setConfigurationParameter(ConfigurationParameter.TslKeyStoreLocation,
          Constant.Production.TSL_KEYSTORE_LOCATION);
      this.setConfigurationParameter(ConfigurationParameter.ValidationPolicy, Constant.Production.VALIDATION_POLICY);
      this.setConfigurationParameter(ConfigurationParameter.OcspSource, Constant.Production.OCSP_SOURCE);
      this.setConfigurationParameter(ConfigurationParameter.SignOcspRequests, "false");
      this.setConfigurationParameter(ConfigurationParameter.PrintValidationReport, "false");
      this.trustedTerritories = Constant.Production.DEFAULT_TRUESTED_TERRITORIES;
      this.setDDoc4JParameter("SIGN_OCSP_REQUESTS", "false");
      setDDoc4JParameter("ALLOWED_OCSP_RESPONDERS_FOR_TM", StringUtils.join(Constant.Production.DEFAULT_OCSP_RESPONDERS, ","));
      this.setConfigurationParameter(ConfigurationParameter.AllowedOcspRespondersForTM, Constant.Production.DEFAULT_OCSP_RESPONDERS);
      this.setConfigurationParameter(ConfigurationParameter.preferAiaOcsp, "false");
      this.loadYamlAiaOCSPs(loadYamlFromResource("defaults/live_aia_ocsp.yaml"), true);
    }
    LOGGER.debug("{} configuration: {}", this.mode, this.registry);
    this.loadInitialConfigurationValues();
  }

  private void loadInitialConfigurationValues() {
    LOGGER.debug("------------------------ LOADING INITIAL CONFIGURATION ------------------------");
    this.setDDoc4JDocConfigurationValue("DIGIDOC_SECURITY_PROVIDER", Constant.DDoc4J.SECURITY_PROVIDER);
    this.setDDoc4JDocConfigurationValue("DIGIDOC_SECURITY_PROVIDER_NAME", Constant.DDoc4J.SECURITY_PROVIDER_NAME);
    this.setDDoc4JDocConfigurationValue("KEY_USAGE_CHECK", Constant.DDoc4J.KEY_USAGE_CHECK);
    this.setDDoc4JDocConfigurationValue("DIGIDOC_OCSP_SIGN_CERT_SERIAL", "");
    this.setDDoc4JDocConfigurationValue("DATAFILE_HASHCODE_MODE", "false");
    this.setDDoc4JDocConfigurationValue("CANONICALIZATION_FACTORY_IMPL",
        Constant.DDoc4J.CANONICALIZATION_FACTORY_IMPLEMENTATION);
    this.setDDoc4JDocConfigurationValue("DIGIDOC_MAX_DATAFILE_CACHED", Constant.DDoc4J.MAX_DATAFILE_CACHED);
    this.setDDoc4JDocConfigurationValue("DIGIDOC_USE_LOCAL_TSL", Constant.DDoc4J.USE_LOCAL_TSL);
    this.setDDoc4JDocConfigurationValue("DIGIDOC_NOTARY_IMPL", Constant.DDoc4J.NOTARY_IMPLEMENTATION);
    this.setDDoc4JDocConfigurationValue("DIGIDOC_TSLFAC_IMPL", Constant.DDoc4J.TSL_FACTORY_IMPLEMENTATION);
    this.setDDoc4JDocConfigurationValue("DIGIDOC_OCSP_RESPONDER_URL", this.getOcspSource());
    this.setDDoc4JDocConfigurationValue("DIGIDOC_FACTORY_IMPL", Constant.DDoc4J.FACTORY_IMPLEMENTATION);
    this.setDDoc4JDocConfigurationValue("DIGIDOC_DF_CACHE_DIR", null);
    this.setConfigurationParameterFromFile("TSL_LOCATION", ConfigurationParameter.TslLocation);
    this.setConfigurationParameterFromFile("TSP_SOURCE", ConfigurationParameter.TspSource);
    this.setConfigurationParameterFromFile("VALIDATION_POLICY", ConfigurationParameter.ValidationPolicy);
    this.setConfigurationParameterFromFile("OCSP_SOURCE", ConfigurationParameter.OcspSource);
    this.setConfigurationParameterFromFile("DIGIDOC_PKCS12_CONTAINER",
        ConfigurationParameter.OcspAccessCertificateFile);
    this.setConfigurationParameterFromFile("DIGIDOC_PKCS12_PASSWD",
        ConfigurationParameter.OcspAccessCertificatePassword);
    this.setConfigurationParameterFromFile("TEMP_FILE_MAX_AGE", ConfigurationParameter.TempFileMaxAgeInMillis);
    this.setConfigurationParameterFromFile("CONNECTION_TIMEOUT", ConfigurationParameter.ConnectionTimeoutInMillis);
    this.setConfigurationParameterFromFile("SOCKET_TIMEOUT", ConfigurationParameter.SocketTimeoutInMillis);
    this.setConfigurationParameterFromFile("SIGN_OCSP_REQUESTS", ConfigurationParameter.SignOcspRequests);
    this.setConfigurationParameterFromFile("TSL_KEYSTORE_LOCATION", ConfigurationParameter.TslKeyStoreLocation);
    this.setConfigurationParameterFromFile("TSL_KEYSTORE_PASSWORD", ConfigurationParameter.TslKeyStorePassword);
    this.setConfigurationParameterFromFile("TSL_CACHE_EXPIRATION_TIME",
        ConfigurationParameter.TslCacheExpirationTimeInMillis);
    this.setConfigurationParameterFromFile("REVOCATION_AND_TIMESTAMP_DELTA_IN_MINUTES",
        ConfigurationParameter.RevocationAndTimestampDeltaInMinutes);
    this.setConfigurationParameterFromFile("ALLOWED_TS_AND_OCSP_RESPONSE_DELTA_IN_MINUTES",
        ConfigurationParameter.AllowedTimestampAndOCSPResponseDeltaInMinutes);
    this.setConfigurationParameterFromFile("SIGNATURE_PROFILE", ConfigurationParameter.SignatureProfile);
    this.setConfigurationParameterFromFile("SIGNATURE_DIGEST_ALGORITHM",
        ConfigurationParameter.SignatureDigestAlgorithm);
    this.setConfigurationParameterFromFile("PRINT_VALIDATION_REPORT", ConfigurationParameter.PrintValidationReport);
    this.setDDoc4JDocConfigurationValue("SIGN_OCSP_REQUESTS", Boolean.toString(this.hasToBeOCSPRequestSigned()));
    this.setDDoc4JDocConfigurationValue("DIGIDOC_PKCS12_CONTAINER", this.getOCSPAccessCertificateFileName());
    this.initOcspAccessCertPasswordForDDoc4J();
    this.setConfigurationParameterFromSystemOrFile(Constant.System.HTTP_PROXY_HOST, ConfigurationParameter.HttpProxyHost);
    this.setConfigurationParameterFromSystemOrFile(Constant.System.HTTP_PROXY_PORT, ConfigurationParameter.HttpProxyPort);
    this.setConfigurationParameterFromSystemOrFile(Constant.System.HTTPS_PROXY_HOST, ConfigurationParameter.HttpsProxyHost);
    this.setConfigurationParameterFromSystemOrFile(Constant.System.HTTPS_PROXY_PORT, ConfigurationParameter.HttpsProxyPort);
    this.setConfigurationParameterFromFile(ConfigurationParameter.HttpProxyUser);
    this.setConfigurationParameterFromFile(ConfigurationParameter.HttpProxyPassword);
    this.setConfigurationParameterFromFile(ConfigurationParameter.SslKeystoreType);
    this.setConfigurationParameterFromFile(ConfigurationParameter.SslTruststoreType);
    this.setConfigurationParameterFromSystemOrFile(Constant.System.JAVAX_NET_SSL_KEY_STORE, ConfigurationParameter.SslKeystorePath);
    this.setConfigurationParameterFromSystemOrFile(Constant.System.JAVAX_NET_SSL_KEY_STORE_PASSWORD, ConfigurationParameter.SslKeystorePassword);
    this.setConfigurationParameterFromSystemOrFile(Constant.System.JAVAX_NET_SSL_TRUST_STORE, ConfigurationParameter.SslTruststorePath);
    this.setConfigurationParameterFromSystemOrFile(Constant.System.JAVAX_NET_SSL_TRUST_STORE_PASSWORD, ConfigurationParameter.SslTruststorePassword);
    this.setConfigurationParameterFromFile(ConfigurationParameter.SslProtocol);
    this.setConfigurationParameterValueListFromFile(ConfigurationParameter.SupportedSslProtocols);
    this.setConfigurationParameterValueListFromFile(ConfigurationParameter.SupportedSslCipherSuites);
    for (ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      this.setConfigurationParameterFromFile(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpProxyHost));
      this.setConfigurationParameterFromFile(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpProxyPort));
      this.setConfigurationParameterFromFile(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpsProxyHost));
      this.setConfigurationParameterFromFile(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpsProxyPort));
      this.setConfigurationParameterFromFile(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpProxyUser));
      this.setConfigurationParameterFromFile(connectionType.mapToSpecificParameter(ConfigurationParameter.HttpProxyPassword));
      this.setConfigurationParameterFromFile(connectionType.mapToSpecificParameter(ConfigurationParameter.SslKeystoreType));
      this.setConfigurationParameterFromFile(connectionType.mapToSpecificParameter(ConfigurationParameter.SslTruststoreType));
      this.setConfigurationParameterFromFile(connectionType.mapToSpecificParameter(ConfigurationParameter.SslKeystorePath));
      this.setConfigurationParameterFromFile(connectionType.mapToSpecificParameter(ConfigurationParameter.SslKeystorePassword));
      this.setConfigurationParameterFromFile(connectionType.mapToSpecificParameter(ConfigurationParameter.SslTruststorePath));
      this.setConfigurationParameterFromFile(connectionType.mapToSpecificParameter(ConfigurationParameter.SslTruststorePassword));
      this.setConfigurationParameterFromFile(connectionType.mapToSpecificParameter(ConfigurationParameter.SslProtocol));
      this.setConfigurationParameterValueListFromFile(connectionType.mapToSpecificParameter(ConfigurationParameter.SupportedSslProtocols));
      this.setConfigurationParameterValueListFromFile(connectionType.mapToSpecificParameter(ConfigurationParameter.SupportedSslCipherSuites));
    }
    this.setConfigurationParameter(ConfigurationParameter.AllowASN1UnsafeInteger, this.getParameter(Constant
        .System.ORG_BOUNCYCASTLE_ASN1_ALLOW_UNSAFE_INTEGER, "ALLOW_UNSAFE_INTEGER"));
    this.setConfigurationParameter(ConfigurationParameter.preferAiaOcsp, this.getParameterFromFile("PREFER_AIA_OCSP"));
    this.loadYamlOcspResponders();
    this.loadYamlTrustedTerritories();
    this.loadYamlTSPs();
    this.loadYamlAiaOCSPs(configurationFromFile, false);
    this.postLoad();
  }

  private void postLoad() {
    String allowASN1UnsafeInteger = this.getConfigurationParameter(ConfigurationParameter.AllowASN1UnsafeInteger);
    if (!StringUtils.isEmpty(allowASN1UnsafeInteger)) {
        System.setProperty(Constant.System.ORG_BOUNCYCASTLE_ASN1_ALLOW_UNSAFE_INTEGER, allowASN1UnsafeInteger);
    } else {
        this.setConfigurationParameter(ConfigurationParameter.AllowASN1UnsafeInteger, "true");
    }
  }

  private Hashtable<String, String> loadDefaultConfigurationFor(Mode mode) {
    // Search for a suitable configuration file from the filesystem first
    for (String file : mode.defaultConfigurationFiles) {
      if (ResourceUtils.isFileReadable(file)) return loadConfiguration(file);
    }
    // If not found from the filesystem, only then search from classpath
    for (String file : mode.defaultConfigurationFiles) {
      if (ResourceUtils.isResourceAccessible(file)) return loadConfiguration(file);
    }
    // If no suitable file found, try to load the last file from the list to get the default error handling and logging
    return loadConfiguration(mode.defaultConfigurationFiles[mode.defaultConfigurationFiles.length - 1]);
  }

  private Hashtable<String, String> loadConfigurationSettings(InputStream stream) {
    try {
      configurationFromFile = new Yaml().loadAs(stream, LinkedHashMap.class);
    } catch (Exception e) {
      ConfigurationException exception = new ConfigurationException("Configuration from "
          + configurationInputSourceName + " is not correctly formatted");
      LOGGER.error(exception.getMessage());
      throw exception;
    } finally {
      IOUtils.closeQuietly(stream);
    }
    if (configurationFromFile == null) {
      configurationFromFile = new LinkedHashMap<>();
    }
    return mapToDDoc4JDocConfiguration();
  }

  private LinkedHashMap<String, Object> loadYamlFromResource(String resource) {
    try (InputStream in = getClass().getClassLoader().getResourceAsStream(resource)) {
      return new Yaml().loadAs(Objects.requireNonNull(in), LinkedHashMap.class);
    } catch (NullPointerException e) {
      String message = "Resource not found: " + resource;
      LOGGER.error(message);
      throw new ConfigurationException(message);
    } catch (Exception e) {
      String message = "Failed to load configuration from resource: " + resource;
      LOGGER.error(message);
      throw new ConfigurationException(message, e);
    }
  }

  private InputStream getResourceAsStream(String certFile) {
    InputStream resourceAsStream = getClass().getClassLoader().getResourceAsStream(certFile);
    if (resourceAsStream == null) {
      String message = "File " + certFile + " not found in classpath.";
      LOGGER.error(message);
      throw new ConfigurationException(message);
    }
    return resourceAsStream;
  }

  private String defaultIfNull(String configParameter, String defaultValue) {
    LOGGER.debug("Parameter: " + configParameter);
    if (configurationFromFile == null) return defaultValue;
    Object value = configurationFromFile.get(configParameter);
    if (value != null) {
      return valueIsAllowed(configParameter, value.toString()) ? value.toString() : "";
    }
    String configuredValue = ddoc4jConfiguration.get(configParameter);
    return configuredValue != null ? configuredValue : defaultValue;
  }

  private boolean valueIsAllowed(String configParameter, String value) {
    List<String> mustBeBooleans = Arrays.asList("SIGN_OCSP_REQUESTS", "KEY_USAGE_CHECK", "DATAFILE_HASHCODE_MODE",
        "DIGIDOC_USE_LOCAL_TSL", "ALLOW_UNSAFE_INTEGER", "PRINT_VALIDATION_REPORT");
    List<String> mustBeIntegers = Arrays.asList("DIGIDOC_MAX_DATAFILE_CACHED", "HTTP_PROXY_PORT");
    boolean errorFound = false;
    if (mustBeBooleans.contains(configParameter)) {
      errorFound = !(this.isValidBooleanParameter(configParameter, value));
    }
    if (mustBeIntegers.contains(configParameter)) {
      errorFound = !(this.isValidIntegerParameter(configParameter, value)) || errorFound;
    }
    return (!errorFound);
  }

  private boolean isValidBooleanParameter(String configParameter, String value) {
    if (!("true".equals(value.toLowerCase()) || "false".equals(value.toLowerCase()))) {
      String errorMessage = "Configuration parameter " + configParameter + " should be set to true or false"
          + " but the actual value is: " + value + ".";
      this.logError(errorMessage);
      return false;
    }
    return true;
  }

  private boolean isValidIntegerParameter(String configParameter, String value) {
    Integer parameterValue;
    try {
      parameterValue = Integer.parseInt(value);
    } catch (Exception e) {
      String errorMessage = "Configuration parameter " + configParameter + " should have an integer value"
          + " but the actual value is: " + value + ".";
      this.logError(errorMessage);
      return false;
    }
    if (configParameter.equals("DIGIDOC_MAX_DATAFILE_CACHED") && parameterValue < -1) {
      String errorMessage = "Configuration parameter " + configParameter + " should be greater or equal -1"
          + " but the actual value is: " + value + ".";
      this.logError(errorMessage);
      return false;
    }
    return true;
  }

  private void loadOCSPCertificates(LinkedHashMap digiDocCA, String caPrefix) {
    String errorMessage;
    @SuppressWarnings("unchecked")
    ArrayList<LinkedHashMap> ocsps = (ArrayList<LinkedHashMap>) digiDocCA.get("OCSPS");
    if (ocsps == null) {
      errorMessage = "No OCSPS entry found or OCSPS entry is empty. Configuration from: "
          + configurationInputSourceName;
      this.logError(errorMessage);
      return;
    }
    int numberOfOCSPCertificates = ocsps.size();
    ddoc4jConfiguration.put(caPrefix + "_OCSPS", String.valueOf(numberOfOCSPCertificates));
    for (int i = 1; i <= numberOfOCSPCertificates; i++) {
      String prefix = caPrefix + "_OCSP" + i;
      LinkedHashMap ocsp = ocsps.get(i - 1);
      List<String> entries = asList("CA_CN", "CA_CERT", "CN", "URL");
      for (String entry : entries) {
        if (!loadOCSPCertificateEntry(entry, ocsp, prefix)) {
          errorMessage = "OCSPS list entry " + i + " does not have an entry for " + entry
              + " or the entry is empty\n";
          this.logError(errorMessage);
        }
      }
      if (!getOCSPCertificates(prefix, ocsp)) {
        errorMessage = "OCSPS list entry " + i + " does not have an entry for CERTS or the entry is empty\n";
        this.logError(errorMessage);
      }
    }
  }

  private void loadYamlTSPs() {
    List<Map<String, Object>> tsps = (List<Map<String, Object>>) this.configurationFromFile.get("TSPS");
    if (tsps == null) {
      this.setConfigurationParameter(ConfigurationParameter.TspsCount, "0");
      return;
    }
    this.setConfigurationParameter(ConfigurationParameter.TspsCount, String.valueOf(tsps.size()));
    List<Pair<String, ConfigurationParameter>> entryPairs = Arrays.asList(
        Pair.of("TSP_SOURCE", ConfigurationParameter.TspCountrySource),
        Pair.of("TSP_KEYSTORE_PATH", ConfigurationParameter.TspCountryKeystorePath),
        Pair.of("TSP_KEYSTORE_TYPE", ConfigurationParameter.TspCountryKeystoreType),
        Pair.of("TSP_KEYSTORE_PASSWORD", ConfigurationParameter.TspCountryKeystorePassword)
    );
    for (int i = 0; i < tsps.size(); i++) {
      Map<String, Object> tsp = tsps.get(i);
      Object country = tsp.get("TSP_C");
      if (country != null) {
        this.tspMap.put(country.toString(), new HashMap<ConfigurationParameter, String>());
        for (Pair<String, ConfigurationParameter> pair : entryPairs) {
          Object entryValue = tsp.get(pair.getKey());
          if (entryValue != null) {
            this.tspMap.get(country.toString()).put(pair.getValue(), entryValue.toString());
          } else {
            this.logError(String.format("No value found for an entry <%s(%s)>", pair.getKey(), i + 1));
          }
        }
      } else {
        this.logError(String.format("No value found for an entry <TSP_C(%s)>", i + 1));
      }
    }
  }

  private void loadYamlAiaOCSPs(LinkedHashMap<String, Object> configurationFromYaml, boolean reset) {
    List<Map<String, Object>> aiaOcspsFromYaml = (List<Map<String, Object>>) configurationFromYaml.get("AIA_OCSPS");
    if (reset) {
      this.aiaOcspMap.clear();
    }
    if (CollectionUtils.isNotEmpty(aiaOcspsFromYaml)) {
      List<Pair<String, ConfigurationParameter>> entryPairs = Arrays.asList(
          Pair.of("ISSUER_CN", ConfigurationParameter.issuerCn),
          Pair.of("OCSP_SOURCE", ConfigurationParameter.aiaOcspSource),
          Pair.of("USE_NONCE", ConfigurationParameter.useNonce)
      );
      for (int i = 0; i < aiaOcspsFromYaml.size(); i++) {
        Map<String, Object> aiaOcspFromYaml = aiaOcspsFromYaml.get(i);
        Object issuerCn = aiaOcspFromYaml.get("ISSUER_CN");
        if (issuerCn != null) {
          Map<ConfigurationParameter, String> aiaOcspMapEntry = this.aiaOcspMap.computeIfAbsent(issuerCn.toString(), k -> new HashMap<>());
          for (Pair<String, ConfigurationParameter> pair : entryPairs) {
            Object entryValue = aiaOcspFromYaml.get(pair.getKey());
            if (entryValue != null) {
              aiaOcspMapEntry.put(pair.getValue(), entryValue.toString());
            } else {
              this.logError(String.format("No value found for an entry <%s(%d)>", pair.getKey(), i + 1));
            }
          }
        } else {
          this.logError(String.format("No value found for an entry <ISSUER_CN(%d)>", i + 1));
        }
      }
    }
    this.setConfigurationParameter(ConfigurationParameter.aiaOcspsCount, String.valueOf(this.aiaOcspMap.size()));
  }

  /**
   * Gives back all configuration parameters needed for DDoc4J
   *
   * @return Hashtable containing DDoc4J configuration parameters
   */

  private Hashtable<String, String> mapToDDoc4JDocConfiguration() {
    LOGGER.debug("loading DDoc4J configuration");
    inputSourceParseErrors = new ArrayList<>();
    loadInitialConfigurationValues();
    reportFileParseErrors();
    return ddoc4jConfiguration;
  }

  private void loadCertificateAuthoritiesAndCertificates() {
    @SuppressWarnings("unchecked")
    ArrayList<LinkedHashMap> digiDocCAs = (ArrayList<LinkedHashMap>) configurationFromFile.get("DIGIDOC_CAS");
    if (digiDocCAs == null) {
      String errorMessage = "Empty or no DIGIDOC_CAS entry";
      this.logError(errorMessage);
      return;
    }

    int numberOfDigiDocCAs = digiDocCAs.size();
    ddoc4jConfiguration.put("DIGIDOC_CAS", String.valueOf(numberOfDigiDocCAs));
    for (int i = 0; i < numberOfDigiDocCAs; i++) {
      String caPrefix = "DIGIDOC_CA_" + (i + 1);
      LinkedHashMap digiDocCA = (LinkedHashMap) digiDocCAs.get(i).get("DIGIDOC_CA");
      if (digiDocCA == null) {
        String errorMessage = "Empty or no DIGIDOC_CA for entry " + (i + 1);
        this.logError(errorMessage);
      } else {
        loadCertificateAuthorityCerts(digiDocCA, caPrefix);
        loadOCSPCertificates(digiDocCA, caPrefix);
      }
    }
  }

  private void logError(String errorMessage) {
    LOGGER.error(errorMessage);
    inputSourceParseErrors.add(errorMessage);
  }

  private void reportFileParseErrors() {
    if (inputSourceParseErrors.size() > 0) {
      StringBuilder errorMessage = new StringBuilder();
      errorMessage.append("Configuration from ");
      errorMessage.append(configurationInputSourceName);
      errorMessage.append(" contains error(s):\n");
      for (String message : inputSourceParseErrors) {
        errorMessage.append(message);
      }
      throw new ConfigurationException(errorMessage.toString());
    }
  }

  private void loadYamlOcspResponders() {
    List<String> responders = getStringListParameterFromFile("ALLOWED_OCSP_RESPONDERS_FOR_TM");
    if (responders != null) {
      String[] respondersValue = responders.toArray(new String[0]);
      this.setConfigurationParameter(ConfigurationParameter.AllowedOcspRespondersForTM, respondersValue);
      this.setDDoc4JDocConfigurationValue("ALLOWED_OCSP_RESPONDERS_FOR_TM", StringUtils.join(respondersValue, ","));
    }
  }

  private void loadYamlTrustedTerritories() {
    List<String> territories = getStringListParameterFromFile("TRUSTED_TERRITORIES");
    if (territories != null) {
      trustedTerritories = territories;
    }
  }

  private String getParameterFromFile(String key) {
    if (this.configurationFromFile == null) {
      return null;
    }
    Object fileValue = this.configurationFromFile.get(key);
    if (fileValue == null) {
      return null;
    }
    String value = fileValue.toString();
    if (this.valueIsAllowed(key, value)) {
      return value;
    }
    return null;
  }

  private List<String> getStringListParameterFromFile(String key) {
    String value = getParameterFromFile(key);
    if (value == null) {
      return null;
    }
    return Arrays.asList(value.split("\\s*,\\s*")); //Split by comma and trim whitespace
  }

  private void setConfigurationParameterFromFile(String fileKey, ConfigurationParameter parameter) {
    String fileValue = this.getParameterFromFile(fileKey);
    if (fileValue != null) {
      this.setConfigurationParameter(parameter, fileValue.toString());
    }
  }

  private void setConfigurationParameterFromFile(ConfigurationParameter parameter) {
    setConfigurationParameterFromFile(parameter.fileKey, parameter);
  }

  private void setConfigurationParameterFromSystemOrFile(String systemKey, ConfigurationParameter parameter) {
    setConfigurationParameter(parameter, getParameter(systemKey, parameter.fileKey));
  }

  private void setConfigurationParameterValueListFromFile(String fileKey, ConfigurationParameter parameter) {
    List<String> fileValues = this.getStringListParameterFromFile(fileKey);
    if (fileValues != null) {
      this.setConfigurationParameter(parameter, fileValues.toArray(new String[fileValues.size()]));
    }
  }

  private void setConfigurationParameterValueListFromFile(ConfigurationParameter parameter) {
    setConfigurationParameterValueListFromFile(parameter.fileKey, parameter);
  }

  private void setDDoc4JDocConfigurationValue(String key, String defaultValue) {
    String value = defaultIfNull(key, defaultValue);
    if (value != null) {
      ddoc4jConfiguration.put(key, value);
    }
  }

  private boolean loadOCSPCertificateEntry(String ocspsEntryName, LinkedHashMap ocsp, String prefix) {
    Object ocspEntry = ocsp.get(ocspsEntryName);
    if (ocspEntry == null) return false;
    ddoc4jConfiguration.put(prefix + "_" + ocspsEntryName, ocspEntry.toString());
    return true;
  }

  @SuppressWarnings("unchecked")
  private boolean getOCSPCertificates(String prefix, LinkedHashMap ocsp) {
    ArrayList<String> certificates = (ArrayList<String>) ocsp.get("CERTS");
    if (certificates == null) {
      return false;
    }
    for (int j = 0; j < certificates.size(); j++) {
      if (j == 0) {
        this.setDDoc4JParameter(String.format("%s_CERT", prefix), certificates.get(0));
      } else {
        this.setDDoc4JParameter(String.format("%s_CERT_%s", prefix, j), certificates.get(j));
      }
    }
    return true;
  }

  private void loadCertificateAuthorityCerts(LinkedHashMap digiDocCA, String caPrefix) {
    LOGGER.debug("Loading CA certificates");
    ArrayList<String> certificateAuthorityCerts = this.getCACertsAsArray(digiDocCA);
    this.setDDoc4JParameter(String.format("%s_NAME", caPrefix), digiDocCA.get("NAME").toString());
    this.setDDoc4JParameter(String.format("%s_TRADENAME", caPrefix), digiDocCA.get("TRADENAME").toString());
    int numberOfCACertificates = certificateAuthorityCerts.size();
    this.setDDoc4JParameter(String.format("%s_CERTS", caPrefix), String.valueOf(numberOfCACertificates));
    for (int i = 0; i < numberOfCACertificates; i++) {
      this.setDDoc4JParameter(String.format("%s_CERT%s", caPrefix, i + 1), certificateAuthorityCerts.get(i));
    }
  }

  @SuppressWarnings("unchecked")
  private ArrayList<String> getCACertsAsArray(LinkedHashMap digiDocCa) {
    return (ArrayList<String>) digiDocCa.get("CERTS");
  }

  private void setConfigurationParameter(ConfigurationParameter parameter, String... value) {
    if (StringUtils.isAllBlank(value)) {
      LOGGER.debug("Parameter <{}> has blank value, hence will not be registered", parameter);
      return;
    }
    LOGGER.debug("Setting parameter <{}> to <{}>", parameter, value);
    this.registry.put(parameter, Arrays.asList(value));
  }

  private <T> T getConfigurationParameter(ConfigurationParameter parameter, Class<T> clazz) {
    String value = this.getConfigurationParameter(parameter);
    if (StringUtils.isNotBlank(value)) {
      if (clazz.isAssignableFrom(Integer.class)) {
        return (T) Integer.valueOf(value);
      } else if (clazz.isAssignableFrom(Long.class)) {
        return (T) Long.valueOf(value);
      } else if (clazz.isAssignableFrom(Boolean.class)) {
        return (T) Boolean.valueOf(value);
      }
      throw new RuntimeException(String.format("Type <%s> not supported", clazz.getSimpleName()));
    }
    return null;
  }

  private String getConfigurationParameter(ConfigurationParameter parameter) {
    if (!this.registry.containsKey(parameter)) {
      LOGGER.debug("Requested parameter <{}> not found", parameter);
      return null;
    }
    String value = this.registry.get(parameter).get(0);
    LOGGER.debug("Requesting parameter <{}>. Returned value is <{}>", parameter, value);
    return value;
  }

  private List<String> getConfigurationValues(ConfigurationParameter parameter) {
    if (!this.registry.containsKey(parameter)) {
      LOGGER.debug("Requested parameter <{}> not found", parameter);
      return null;
    }
    List<String> values = this.registry.get(parameter);
    LOGGER.debug("Requesting parameter <{}>. Returned value is <{}>", parameter, values);
    return values;
  }

  private void initOcspAccessCertPasswordForDDoc4J() {
    char[] ocspAccessCertificatePassword = this.getOCSPAccessCertificatePassword();
    if (ocspAccessCertificatePassword != null && ocspAccessCertificatePassword.length > 0) {
      this.setDDoc4JDocConfigurationValue(Constant.DDoc4J.OCSP_PKCS_12_PASSWORD,
          String.valueOf(ocspAccessCertificatePassword));
    }
  }

  /**
   * Get String value through JVM parameters or from configuration file
   *
   * @param systemKey jvm value key .
   * @param fileKey   file value key.
   * @return String value from JVM parameters or from file
   */
  private String getParameter(String systemKey, String fileKey) {
    String valueFromJvm = System.getProperty(systemKey);
    String valueFromFile = this.getParameterFromFile(fileKey);
    this.log(valueFromJvm, valueFromFile, systemKey, fileKey);
    return valueFromJvm != null ? valueFromJvm : valueFromFile;
  }

  private void setDDoc4JParameter(String key, String value) {
    LOGGER.debug("Setting DDoc4J parameter <{}> to <{}>", key, value);
    this.ddoc4jConfiguration.put(key, value);
  }

  private void log(Object jvmParam, Object fileParam, String sysParamKey, String fileKey) {
    if (jvmParam != null) {
      LOGGER.debug(String.format("JVM parameter <%s> detected and applied with value <%s>", sysParamKey, jvmParam));
    }
    if (jvmParam == null && fileParam != null) {
      LOGGER.debug(
          String.format("YAML file parameter <%s> detected and applied with value <%s>", fileKey, fileParam));
    }
  }

}
