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

import eu.europa.esig.dss.enumerations.MimeType;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.asic.asics.AsicSCompositeContainer;
import org.digidoc4j.utils.ContainerUtils;
import org.digidoc4j.utils.MimeTypeUtil;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * A builder for creating {@link CompositeContainer}s by nesting an existing container into another container.
 * A nested inner container becomes a data file for the nesting outer container.
 * <p>The builder can be created from either:<ul>
 * <li>an existing {@link Container} object via {@link #fromContainer(Container, String)}</li>
 * <li>a path to an existing container file via {@link #fromContainerFile(String)}</li>
 * <li>an input stream of an existing container via {@link #fromContainerStream(InputStream, String)}</li>
 * </ul>
 * <p>The builder currently supports creating:<ul>
 * <li>a timestamped ASiC-S container via {@link #buildTimestamped(Consumer)}</li>
 * </ul>
 *
 * @see CompositeContainer
 */
public class CompositeContainerBuilder {

  private static final String CONTAINER_NULL_MESSAGE = "Container cannot be null";
  private static final String CONTAINER_NAME_NULL_MESSAGE = "Container file name cannot be null";
  private static final String CONTAINER_PATH_NULL_MESSAGE = "Container file path cannot be null";
  private static final String CONTAINER_STREAM_NULL_MESSAGE = "Container input stream cannot be null";

  private Configuration configuration;
  private Container nestedContainer;
  private String nestedContainerFileName;
  private String nestedContainerFilePath;
  private InputStream nestedContainerInputStream;

  /**
   * Creates an instance of a composite container builder from an existing {@link Container} object.
   * The specified container will be nested as a data file into a nesting composite container.
   * The name of the data file will be specified by {@code containerFileName} parameter.
   * <p><b>NB:</b><ul>
   * <li>The specified nested container must support serialization via {@link Container#saveAsStream()}!</li>
   * <li>In case the to-be-nested container has already been serialized and it does not need any further modifications,
   * it is recommended to use {@link #fromContainerFile(String)} or {@link #fromContainerStream(InputStream, String)}
   * instead. {@link Container#saveAsStream()} may produce a binary representation that is not identical to the
   * original serialized form of the container!</li>
   * <li>The composite container this builder will create, will use the same configuration as the specified
   * to-be-nested container uses, unless overridden via {@link #withConfiguration(Configuration)}.</li>
   * </ul>
   *
   * @param container an existing container object to be nested
   * @param containerFileName file name of the to-be-nested container
   * @return builder for creating a composite container
   */
  public static CompositeContainerBuilder fromContainer(Container container, String containerFileName) {
    CompositeContainerBuilder builder = new CompositeContainerBuilder();
    builder.nestedContainer = Objects.requireNonNull(container, CONTAINER_NULL_MESSAGE);
    builder.nestedContainerFileName = validateFileName(Objects.requireNonNull(containerFileName, CONTAINER_NAME_NULL_MESSAGE));
    return builder;
  }

  /**
   * Creates an instance of a composite container builder from an existing container file.
   * The specified container will be nested as a data file into a nesting composite container.
   * The name of the data file will be determined from the specified file path.
   *
   * @param containerFilePath path to an existing container file to be nested
   * @return builder for creating a composite container
   */
  public static CompositeContainerBuilder fromContainerFile(String containerFilePath) {
    CompositeContainerBuilder builder = new CompositeContainerBuilder();
    builder.nestedContainerFilePath = Objects.requireNonNull(containerFilePath, CONTAINER_PATH_NULL_MESSAGE);
    validateFileName(containerFilePath);
    return builder;
  }

  /**
   * Creates an instance of a composite container builder from the input stream of an existing container.
   * The specified container will be nested as a data file into a nesting composite container.
   * The name of the data file will be specified by {@code containerFileName} parameter.
   *
   * @param containerInputStream input stream of an existing container to be nested
   * @param containerFileName file name of the to-be-nested container
   * @return builder for creating a composite container
   */
  public static CompositeContainerBuilder fromContainerStream(InputStream containerInputStream, String containerFileName) {
    CompositeContainerBuilder builder = new CompositeContainerBuilder();
    builder.nestedContainerInputStream = Objects.requireNonNull(containerInputStream, CONTAINER_STREAM_NULL_MESSAGE);
    builder.nestedContainerFileName = validateFileName(Objects.requireNonNull(containerFileName, CONTAINER_NAME_NULL_MESSAGE));
    return builder;
  }

  /**
   * Builds a timestamped composite container.
   * The resulting composite container will contain the initially specified container as its data file,
   * which will be covered by a freshly taken timestamp token.
   * The type of the resulting container will be ASiC-S.
   * <p><b>NB:</b> The specified timestamp builder configurator should not call
   * {@link TimestampBuilder#invokeTimestamping()} directly!
   *
   * @param timestampBuilderConfigurator callback for configuring the timestamp builder used for creating a timestamp
   * @return timestamped composite container
   *
   * @see TimestampBuilder
   */
  public CompositeContainer buildTimestamped(Consumer<TimestampBuilder> timestampBuilderConfigurator) {
    Pair<DataFile, Container> serializedAndParsedContainerPair = createSerializedAndParsedContainerPair();
    AsicSCompositeContainer nestingContainer = new AsicSCompositeContainer(
            serializedAndParsedContainerPair.getLeft(),
            serializedAndParsedContainerPair.getRight(),
            getConfiguration()
    );

    TimestampBuilder timestampBuilder = TimestampBuilder.aTimestamp(nestingContainer);
    timestampBuilderConfigurator.accept(timestampBuilder);

    nestingContainer.addTimestamp(timestampBuilder.invokeTimestamping());
    return nestingContainer;
  }

  /**
   * Specifies the configuration to be used by the container being built.
   *
   * @param configuration configuration to use for building the container
   * @return this builder
   */
  public CompositeContainerBuilder withConfiguration(Configuration configuration) {
    this.configuration = configuration;
    return this;
  }

  private Pair<DataFile, Container> createSerializedAndParsedContainerPair() {
    Container container = this.nestedContainer;
    DataFile dataFile;

    if (container != null) {
      dataFile = serializeContainer(container, getNestedContainerFileName());
    } else if (nestedContainerInputStream != null) {
      // Input stream can be consumed only once, so it must be read into an in-memory data file first
      //  in order to preserve the exact binary form of the initial (nestable) container,
      //  after which it can be parsed without creating additional copies of the whole byte array of the input.
      dataFile = new DataFile(nestedContainerInputStream, getNestedContainerFileName(), getNestedContainerMimeTypeString());
      container = parseContainer(dataFile, getConfiguration());
      // Container type dependent mime-type is available only after the container has been parsed,
      //  so the data file representing the container must be mutated after it has been created.
      updateSerializedContainerMimeType(dataFile, container);
    } else if (nestedContainerFilePath != null) {
      container = ContainerOpener.open(nestedContainerFilePath, getConfiguration());
      // Use file-based data file in order to not create another in-memory copy of the container.
      dataFile = new DataFile(nestedContainerFilePath, ContainerUtils.getMimeTypeStringFor(container));
    } else {
      throw new IllegalStateException("Nested container not specified");
    }

    return new ImmutablePair<>(dataFile, container);
  }

  private Configuration getConfiguration() {
    return Optional
            .ofNullable(configuration)
            .orElseGet(() -> Optional
                    .ofNullable(nestedContainer)
                    .map(Container::getConfiguration)
                    .orElseGet(Configuration::getInstance)
            );
  }

  private String getNestedContainerFileName() {
    return Optional
            .ofNullable(nestedContainerFileName)
            .orElseGet(() -> Optional
                    .ofNullable(nestedContainerFilePath)
                    .map(FilenameUtils::getName)
                    .orElseThrow(() -> new IllegalStateException("Nested container file name is missing"))
            );
  }

  private String getNestedContainerMimeTypeString() {
    return MimeType.fromFileName(getNestedContainerFileName()).getMimeTypeString();
  }

  private CompositeContainerBuilder() {
  }

  private static Container parseContainer(DataFile serializedContainer, Configuration configuration) {
    try (InputStream inputStream = serializedContainer.getStream()) {
      return ContainerOpener.open(inputStream, configuration);
    } catch (IOException e) {
      throw new TechnicalException("Failed to parse container", e);
    }
  }

  private static DataFile serializeContainer(Container container, String fileName) {
    try (InputStream inputStream = container.saveAsStream()) {
      return new DataFile(inputStream, fileName, ContainerUtils.getMimeTypeStringFor(container));
    } catch (IOException e) {
      throw new TechnicalException("Failed to serialize container", e);
    }
  }

  private static void updateSerializedContainerMimeType(DataFile serializedContainer, Container container) {
    String determinedMimeTypeString = ContainerUtils.getMimeTypeStringFor(container);
    if (!StringUtils.equals(serializedContainer.getMediaType(), determinedMimeTypeString)) {
      serializedContainer.getDocument().setMimeType(MimeTypeUtil.fromMimeTypeString(determinedMimeTypeString));
    }
  }

  private static String validateFileName(String fileName) {
    String sanitizedFileName = FilenameUtils.getName(fileName);
    if (StringUtils.isBlank(sanitizedFileName)) {
      throw new IllegalArgumentException("File name cannot be empty");
    }
    return sanitizedFileName;
  }

}
