package org.digidoc4j;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.util.HashMap;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Offers registry for configuration parameters.
 * <p>
 * Dedicated serialization and deserialization is provided to identify configuration changes when object is
 * deserialized in different environment having other configuration setup. This is a workaround when no singleton
 * {@link Configuration} object instance is used e.g. {@link BDocContainer} has embedded
 * {@link Configuration}
 * </p>
 *
 * @author Janar Rahumeel (CGI Estonia)
 */

public class ConfigurationRegistry extends HashMap<ConfigurationParameter, String> {

  private static final Logger logger = LoggerFactory.getLogger(ConfigurationRegistry.class);
  private static final long serialVersionUID = 7829136421415567565L;
  private String sealValue = "";

  protected String generateSealValue() {
    // TODO can we use hashcode?
    return this.seal();
  }

  protected String getSealValue() {
    return this.sealValue;
  }

  private void writeObject(ObjectOutputStream stream) throws IOException {
    for (ConfigurationParameter parameter : ConfigurationParameter.values()) {
      String value;
      if (this.containsKey(parameter)) {
        value = String.format("%s|%s", parameter, this.get(parameter).replaceAll("[\\\\]*[\\|]", "\\\\|"));
      } else {
        value = String.format("%s", parameter);
      }
      logger.trace("Writing {}", value);
      stream.writeUTF(value);
    }
    stream.writeUTF(this.generateSealValue());
  }

  private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
    for (int i = 0; i <= ConfigurationParameter.values().length; i++) {
      try {
        String token = stream.readUTF();
        try {
          String[] s = StringUtils.split(token, "|");
          logger.trace("Reading {}", s[0]);
          this.put(ConfigurationParameter.valueOf(s[0]), s[1].replaceAll("[\\\\]+[\\|]", "\\|"));
        } catch (IndexOutOfBoundsException ignore) {
          logger.trace("Ignoring, no value: {}", ignore.getMessage());
        } catch (IllegalArgumentException e) {
          logger.debug("Seal <{}> found", token);
          this.sealValue = token;
        }
      } catch (IOException ignore) {
        if (logger.isDebugEnabled()) {
          logger.warn("Error", ignore);
        } else {
          logger.warn("Error: {}", ignore.getMessage());
        }
      }
    }
    this.checkCurrentConfiguration();
  }

  private void checkCurrentConfiguration() {
    ConfigurationRegistry registry = Configuration.getInstance().getRegistry();
    String currentSealValue = registry.generateSealValue();
    if (logger.isDebugEnabled()) {
      logger.debug("Seal {} {} {}", this.sealValue, this.sealValue.equals(currentSealValue) ? "==" : "!=", currentSealValue);
    }
    if (!this.sealValue.equals(currentSealValue)) {
      logger.info("Overwriting deserialized registry with current one");
      this.clear();
      this.putAll(registry);
    }
  }

  private String seal() {
    try {
      return Hex.encodeHexString(MessageDigest.getInstance("MD5").digest(this.calculateToken().getBytes("UTF-8")));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private String calculateToken() {
    StringBuilder sb = new StringBuilder();
    for (ConfigurationParameter parameter : ConfigurationParameter.values()) {
      sb.append(String.format("%s", this.get(parameter)));
    }
    return sb.toString();
  }

}
