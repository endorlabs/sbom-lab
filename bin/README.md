Install SBOM generators using the following links and make sure to save them
using the mentioned filenames (to match the names used in `eval-sboms.sh`):

- https://github.com/eclipse/jbom/releases/ should be saved as `jbom.jar`
- https://github.com/anchore/syft/releases/ should be saved as `syft`
- https://github.com/aquasecurity/trivy/releases should be saved as `trivy`

The CycloneDX Maven Plugin will be downloaded by Maven and does not need to be
installed.

Other open source SBOM generators that can be included in the future (taken from [CycloneDX Tool Center](https://cyclonedx.org/tool-center/)):
- [Codenotary Community Attestation Service (CAS)](https://github.com/codenotary/cas) (requires a service account)
- [Eclipse SW360 Antenna](https://www.eclipse.org/antenna) (archived in Feb 2021)
- [Scan](https://github.com/ShiftLeftSecurity/sast-scan)
- [Build Info](https://www.buildinfo.org/)