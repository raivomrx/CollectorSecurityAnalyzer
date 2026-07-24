# Privacy Model

The default policy is privacy-preserving:

```json
{
  "includeHostname": false,
  "hashUsername": true,
  "hashTenantId": true,
  "includeIpAddresses": false,
  "includeMacAddresses": false,
  "includeSoftwareInventory": true,
  "includeBrowserExtensions": false,
  "includeCertificateSubjects": false,
  "includeLocalAdminNames": false,
  "includeFilePaths": "REDACT_USER_PROFILE",
  "includeRawRegistryValues": false
}
```

The endpoint applies strict privacy collection. The Console scans evidence,
capability results, and collection logs before acceptance. Violations return
`REJECTED_SENSITIVE_DATA`; values are not copied into logs.

The scanner rejects credential fields and recognizable private-key,
authorization, cookie, and password material while allowing boolean presence
and policy metadata such as `recoveryPasswordPresent` or password policy
length.
