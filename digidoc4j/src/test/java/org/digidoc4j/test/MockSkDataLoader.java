/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.test;

import org.digidoc4j.Configuration;
import org.digidoc4j.impl.asic.SkDataLoader;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class MockSkDataLoader extends SkDataLoader {

  private String sslKeystorePath;
  private String sslKeystoreType;
  private String sslKeystorePassword;
  private String sslTruststorePath;
  private String sslTruststoreType;
  private String sslTruststorePassword;
  private boolean isSslKeystoreTypeSet;
  private boolean sslKeystorePasswordSet;
  private boolean sslTruststoreTypeSet;
  private boolean sslTruststorePasswordSet;

  public MockSkDataLoader(Configuration configuration) {
    super(configuration);
  }

  public String getSslKeystorePath() {
    return sslKeystorePath;
  }

  public void setSslKeystorePath(String sslKeystorePath) {
    super.setSslKeystorePath(sslKeystorePath);
    this.sslKeystorePath = sslKeystorePath;
  }

  public String getSslKeystoreType() {
    return sslKeystoreType;
  }

  public void setSslKeystoreType(String sslKeystoreType) {
    super.setSslKeystoreType(sslKeystoreType);
    this.sslKeystoreType = sslKeystoreType;
    this.isSslKeystoreTypeSet = true;
  }

  public String getSslKeystorePassword() {
    return sslKeystorePassword;
  }

  public void setSslKeystorePassword(String sslKeystorePassword) {
    super.setSslKeystorePassword(sslKeystorePassword);
    this.sslKeystorePassword = sslKeystorePassword;
    this.sslKeystorePasswordSet = true;
  }

  public String getSslTruststorePath() {
    return sslTruststorePath;
  }

  public void setSslTruststorePath(String sslTruststorePath) {
    this.sslTruststorePath = sslTruststorePath;
    super.setSslTruststorePath(sslTruststorePath);
  }

  public String getSslTruststoreType() {
    return sslTruststoreType;
  }

  public void setSslTruststoreType(String sslTruststoreType) {
    super.setSslTruststoreType(sslTruststoreType);
    this.sslTruststoreType = sslTruststoreType;
    this.sslTruststoreTypeSet = true;
  }

  public String getSslTruststorePassword() {
    return sslTruststorePassword;
  }

  public void setSslTruststorePassword(String sslTruststorePassword) {
    super.setSslTruststorePassword(sslTruststorePassword);
    this.sslTruststorePassword = sslTruststorePassword;
    this.sslTruststorePasswordSet = true;
  }

  public boolean isSslKeystoreTypeSet() {
    return isSslKeystoreTypeSet;
  }

  public boolean isSslKeystorePasswordSet() {
    return sslKeystorePasswordSet;
  }

  public boolean isSslTruststoreTypeSet() {
    return sslTruststoreTypeSet;
  }

  public boolean isSslTruststorePasswordSet() {
    return sslTruststorePasswordSet;
  }

}
