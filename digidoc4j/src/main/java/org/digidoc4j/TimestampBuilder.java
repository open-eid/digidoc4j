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

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.UnsupportedFormatException;
import org.digidoc4j.impl.asic.asics.AsicSContainerTimestampBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Optional;

import static org.digidoc4j.Constant.ASICS_CONTAINER_TYPE;

/**
 * A builder for creating timestamps that cover the contents of specific containers.
 */
public abstract class TimestampBuilder implements Serializable, TimestampParameters {

  private static final Logger logger = LoggerFactory.getLogger(TimestampBuilder.class);

  private DigestAlgorithm referenceDigestAlgorithm;
  private DigestAlgorithm timestampDigestAlgorithm;
  private String tspSource;

  /**
   * Creates an instance of a timestamp builder for the contents of the specified container.
   *
   * @param container container to be timestamped
   * @return builder for creating a timestamp
   */
  public static TimestampBuilder aTimestamp(Container container) {
    String containerType = container.getType();
    if (StringUtils.equalsIgnoreCase(containerType, ASICS_CONTAINER_TYPE)) {
      return new AsicSContainerTimestampBuilder(container);
    } else {
      logger.error("Unsupported container type: {}", containerType);
      throw new UnsupportedFormatException(containerType);
    }
  }

  /**
   * Invokes timestamping process based on the current state of this builder and returns the newly created timestamp.
   *
   * @return the newly created timestamp
   */
  public Timestamp invokeTimestamping() {
    ensureTimestampingIsPossible();
    return invokeTimestampingProcess();
  }

  /**
   * Configures the reference digest algorithm to be used by this builder.
   * Reference digest algorithm is used when a timestamp will cover a collection of references (e.g. an
   * {@code ASiCArchiveManifest.xml} file), and each reference needs to incorporate the digest of the entity it
   * references.
   * For more information about the defaults used when this is not configured, see
   * {@link #getReferenceDigestAlgorithm()}.
   *
   * @param digestAlgorithm reference digest algorithm
   * @return builder for creating a timestamp
   */
  public TimestampBuilder withReferenceDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
    referenceDigestAlgorithm = digestAlgorithm;
    return this;
  }

  /**
   * Returns the configured reference digest algorithm, falling back to the value from
   * {@link Configuration#getArchiveTimestampReferenceDigestAlgorithm()}, falling back to the value from
   * {@link #getTimestampDigestAlgorithm()}.
   *
   * @return configured reference digest algorithm or a default
   */
  @Override
  public DigestAlgorithm getReferenceDigestAlgorithm() {
    return Optional
            .ofNullable(referenceDigestAlgorithm)
            .orElseGet(() -> Optional
                    .ofNullable(getConfiguration().getArchiveTimestampReferenceDigestAlgorithm())
                    .orElseGet(this::getTimestampDigestAlgorithm)
            );
  }

  /**
   * Configures the timestamp digest algorithm to be used by this builder.
   * For more information about the defaults used when this is not configured, see
   * {@link #getTimestampDigestAlgorithm()}.
   *
   * @param digestAlgorithm timestamp digest algorithm
   * @return builder for creating a timestamp
   */
  public TimestampBuilder withTimestampDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
    timestampDigestAlgorithm = digestAlgorithm;
    return this;
  }

  /**
   * Returns the configured timestamp digest algorithm, falling back to the value from
   * {@link Configuration#getArchiveTimestampDigestAlgorithm()}, falling back to the value of
   * {@link Constant.Default#ARCHIVE_TIMESTAMP_DIGEST_ALGORITHM}.
   *
   * @return configured timestamp digest algorithm or a default
   */
  @Override
  public DigestAlgorithm getTimestampDigestAlgorithm() {
    return Optional
            .ofNullable(timestampDigestAlgorithm)
            .orElseGet(() -> Optional
                    .ofNullable(getConfiguration().getArchiveTimestampDigestAlgorithm())
                    .orElse(Constant.Default.ARCHIVE_TIMESTAMP_DIGEST_ALGORITHM)
            );
  }

  /**
   * Configures the TSP source URL string to be used by this builder.
   * For more information about the defaults used when this is not configured, see {@link #getTspSource()}.
   *
   * @param tspSource TSP source URL string
   * @return builder for creating a timestamp
   */
  public TimestampBuilder withTspSource(String tspSource) {
    this.tspSource = tspSource;
    return this;
  }

  /**
   * Returns the configured TSP source URL string, falling back to the value from
   * {@link Configuration#getTspSourceForArchiveTimestamps()}.
   *
   * @return configured TSP source URL string or a default
   */
  @Override
  public String getTspSource() {
    return Optional
            .ofNullable(tspSource)
            .orElseGet(getConfiguration()::getTspSourceForArchiveTimestamps);
  }

  /**
   * Returns the configuration object bound to this builder.
   *
   * @return the configuration object bound to this builder
   */
  protected abstract Configuration getConfiguration();

  /**
   * Ensures that this builder is in a proper state to invoke timestamping.
   */
  protected abstract void ensureTimestampingIsPossible();

  /**
   * Invokes the internal timestamping process and returns the newly created timestamp.
   *
   * @return the newly created timestamp
   */
  protected abstract Timestamp invokeTimestampingProcess();

}
