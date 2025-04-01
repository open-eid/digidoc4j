# TSL file templates for testing

* `test-lotl-EE-4.xml.template` - [Estonian test LOTL](https://open-eid.github.io/test-TL/tl-mp-test-EE.xml) with
  sequence number 4. Contains the following placeholders:
  - `{TSL_VERSION_IDENTIFIER}` in the `<TSLVersionIdentifier>` tag.
  - `{OTHER_TSL_CERTIFICATE_B64}` in the `<X509Certificate>` tag of the service digital identity block of the pointer to
    other TSL block of `EE_T` territory. Represents the signer certificate of the `EE_T` trusted list in base64-encoded
    form.
  - `{OTHER_TSL_LOCATION}` in the `<TSLLocation>` tag of the pointer to other TSL block of `EE_T` territory. Represents
    the URL of the `EE_T` trusted list.
* `test-tl-EE_T-30.xml.template` - [Estonian test trusted list](https://open-eid.github.io/test-TL/EE_T.xml) (territory
  `EE_T`) with sequence number 30. Contains the following placeholders:
  - `{TSL_VERSION_IDENTIFIER}` in the `<TSLVersionIdentifier>` tag.