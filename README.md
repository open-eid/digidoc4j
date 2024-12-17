<img src="digidoc4j/src/main/doc/resources/Co-funded_by_the_European_Union.jpg" width="350" height="200" alt="Co-funded by the European Union">

# DigiDoc4j
DigiDoc4j is a Java library for digitally signing documents and creating digital signature containers of signed documents.

# Features
* Creating ASiC-E and ASiC-S containers
* Validating ASiC-E, ASiC-S, BDOC, and DDOC containers
* Creating and validating detached XAdES signatures
* Creating and validating timestamp tokens

# How to use it
* Take a look at the [examples](https://github.com/open-eid/digidoc4j/wiki/Examples-of-using-it)
* See the full [DigiDoc4j API](http://open-eid.github.io/digidoc4j/) description
* Explore the [Wiki](https://github.com/open-eid/digidoc4j/wiki) section
* Download the latest [release](https://github.com/open-eid/digidoc4j/releases)
* See the [library development guide](https://github.com/open-eid/digidoc4j/wiki/Development). Your contribution and pull requests are more than welcome

# ASiC-E (Associated Signature Container Extended) container format
* Has **.asice** or **.sce** extension.
* This format is default format since 2019.
* ASIC-E containers are in compliance with EU standards.
* Signatures are stored in **XAdES** format.
* Supports following signature profiles:
  * **B_BES** - Basic signature (not considered valid by DigiDoc4j validation rules).
  * **T** (Time) - Signature with **time-stamp** (not considered valid by DigiDoc4j validation rules).
  * **LT** (Long Term) - Signature with **time-stamp** and **OCSP** (both "regular" and AIA OCSP are supported).
  * **LTA** (Long Term Archival) - Signature has additional **archival time-stamp**(s) to LT profile.
* **.asice** or **.sce** file is in fact a ZIP container with the signed files, the signatures and the protocol control information and can basically be opened by any program that recognizes the ZIP format.
* It is recommended not to use special characters in the data file’s name, i.e. it is suggested to use only the characters that are categorized as “unreserved” according to RFC3986 (https://datatracker.ietf.org/doc/html/rfc3986).

# BDOC (Estonian specific implementation of Associated Signature Container Extended) container format
The support for creating BDOC-specific **time-mark** signatures was removed since DigiDoc4j version **5.2.0** in relation to
[discontinuation of **time-mark**-capable OCSP responders in 2023](https://www.id.ee/en/article/ria-stops-supporting-the-creation-of-the-bdoc-tm-digital-signature-format-in-the-software-it-develops/).

* Has **.bdoc** extension
* BDOC is a digital signature format developed in 2014 to replace the old, DDOC (DigiDoc) digital signature format.
* This format has been used as a default digital signature format in Estonia since 2015 until end of 2018.
* BDOC container is based on **ASiC-E** standard.
* Signatures are stored in **XAdES** format.
* Supports signature profiles:
  * **B_EPES** - Basic signature with signature policy defined (not considered valid by DigiDoc4j validation rules).
    **B_EPES** signing support in DigiDoc4j was removed since version **5.2.0**.
  * **LT_TM** (Long Term TimeMark) - Signature has **time-mark** ensuring long-term provability of the authenticity of the signature.
    **LT_TM** signing support in DigiDoc4j was removed since version **5.2.0**.
    * It is based on **XAdES baseline LT** signature format.
* **.bdoc** file is in fact a ZIP container with the signed files, the signatures and the protocol control information and can basically be opened by any program that recognizes the ZIP format.
* It is recommended not to use special characters in the data file’s name, i.e. it is suggested to use only the characters that are categorized as “unreserved” according to RFC3986 (https://datatracker.ietf.org/doc/html/rfc3986).

# ASiC-S (Associated Signature Container Simple) container format
* Has **.asics** or **.scs** extension
* Container associates one data file with either:
  - one signature file containing one or more XAdES detached digital signature(s) that apply to it; or
  - one or more time assertion file(s) containing a time assertion that apply to it.
* This format is used for timestamping the old DDOC containers in order to prove the integrity of documents.
* Starting from DigiDoc4j version **6.0.0-RC.1**, this format is also supported for timestamping ASiC and BDOC
  containers in order to prove the integrity of their contents.

# DDOC container format
* Has **.ddoc** extension
* An old DigiDoc digital signature format
* Since year 2015 it's recommended not to sign documents in the DDOC format. DDOC signing support in Digidoc4j was removed in 2018.
* It is based on XML Advanced Electronic Signatures (**XAdES**) format, corresponding to  profile XAdES-X-L
* The DigiDoc container includes the source files (the files that were signed) as well as the signatures that are related to the signed file(s)
* Every signature contains the certificate, validity confirmation and the validity confirmation service certificate.

# Documentation
* [DigiDoc4j API](http://open-eid.github.io/digidoc4j/)
* [Examples](https://github.com/open-eid/digidoc4j/wiki/Examples-of-using-it)
* [Wiki](https://github.com/open-eid/digidoc4j/wiki)
* [Architecture of ID-software](http://open-eid.github.io/)
* [Digital signature formats](http://www.id.ee/index.php?id=36108)
* [BDOC 2.1.2 specification](https://www.id.ee/wp-content/uploads/2021/06/bdoc-spec212-eng.pdf)
* [DDOC specification](https://www.id.ee/wp-content/uploads/2020/08/digidoc_format_1.3.pdf)

# Requirements
* Java **8** or higher (since version 4.0.0-RC.1)
* Internet access to external services
  * OCSP (Online Certificate Status Protocol) - AIA OCSP URL from signer's certificate or default fallback value
    http://ocsp.sk.ee (for more information, see
    [here](https://github.com/open-eid/digidoc4j/wiki/Questions-&-Answers#usage-of-aia-ocsp-for-timestamp-based-asic-e-containers-since-release-310))
  * EU TSL (European Commission's Trusted Status List) - default value https://ec.europa.eu/tools/lotl/eu-lotl.xml (for
    more information, see [here](https://github.com/open-eid/digidoc4j/wiki/Examples-of-using-it#using-configuration))
  * All the EU member states' TL servers referred in the EU TSL. Note that this list may change.
    (e.g. https://sr.riik.ee/tsl/estonian-tsl.xml, https://sedediatid.mineco.gob.es/Prestadores/TSL/TSL.xml, https://dp.trustedlist.fi/fi-tl.xml etc.)
  * TSA (Time Stamping Authority) - default value http://tsa.sk.ee (for more information, see
    [here](https://github.com/open-eid/digidoc4j/wiki/Examples-of-using-it#using-configuration))
  * AIA (Authority Information Access) CA issuers - missing certificates of certificate chains downloaded from the URLs
    referred to in existing certificates
  * Signature Policy documents, if applicable (e.g. https://www.sk.ee/repository/bdoc-spec21.pdf)

## Maven
You can use the library as a Maven dependency from the Maven Central (http://mvnrepository.com/artifact/org.digidoc4j/digidoc4j)

```xml
<dependency>
	<groupId>org.digidoc4j</groupId>
	<artifactId>digidoc4j</artifactId>
	<version>6.x.x</version>
</dependency>
```

# Licence
* LGPL (GNU Library General Public License, see LICENSE.LGPL)
* © Estonian Information System Authority

## Support
Official builds are provided through [releases](https://github.com/open-eid/digidoc4j/releases).
If you want support, you need to be using official builds.
For assistance, contact us by email [help@ria.ee](mailto:help@ria.ee).
Additional information can be found in [wiki Q&A](https://github.com/open-eid/digidoc4j/wiki/Questions-&-Answers) and
on [ID.ee portal](https://www.id.ee/en/rubriik/digidoc-libraries/).

For staying up to date with news impacting services and applications that use the DigiDoc4j library,
[join DigiDoc4j library newsletter](https://www.id.ee/en/article/join-dd4j-library-newsletter/).

Source code is provided on "as is" terms with no warranty (see license for more information).
Do not file GitHub issues with generic support requests.
