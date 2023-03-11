# Welcome to Cnert's documentation!

Cnert creates TLS private keys, CSRs, private CAs, intermediate CAs and
certificates for testing purposes.


## Usage

Create a CA:
    ```python
    ca = cnert.CA()
    ```

Issue a certificate:
    ```python
    ca = cnert.CA()
    cert = ca.issue_cert()
    cert.pem_str
    ```

Issue certificate from a intermediate:
    ```python
    ca = cnert.CA()
    intermediate = ca.issue_intermediate()
    cert = intermediate.issue_cert()
    ```

Create a CA with custom subject attributes:
    ```python
    subject_attr = cnert.NameAttrs(
        COMMON_NAME="My common name",
        COUNTRY_NAME="AQ",
        EMAIL_ADDRESS="someone@example.com",
    )
    ca = cnert.CA(subject_attrs=subject_attrs)
    assert ca.cert.COMMON_NAME == "My common name"
    assert ca.cert.COUNTRY_NAME == "AQ"
    assert ca.cert.EMAIL_ADDRESS == "EMAIL_ADDRESS"

    ca.x509_name

    ```

<!-- Create CSR: -->
<!--     ```python -->
<!--     csr = cnert.CSR() -->
<!--     ``` -->

<!-- Create a certificate from a CSR: -->
<!--     ```python -->
<!--     csr = cnert.CSR() -->
<!--     ca = cnert.CA() -->
<!--     cert = ca.issue_cert(csr=csr) -->
<!--     ``` -->


Our homemade Certificate Authority (CA) has certificate and it's properties are
available for testing purposes, with some defaults:

    ```python
    assert ca.cert.subject_attrs.COMMON_NAME == "CA"
    ```

Set *Name Attributes* at initialisation:

    ```python
    subject_attrs = cnert.NameAttrs(COMMON_NAME="My CA")
    ca = cnert.CA(subject_attrs=subject_attrs)
    assert ca.cert.subject_attrs.COMMON_NAME = "My CA"
    ```
