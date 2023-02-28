This repository facilitates the evaluation and comparison of SBOM generators for
Java/Maven development projects.

The bash script `eval-sboms.sh` processes dependencies of a given Maven project
on one side, and creates SBOMs in CycloneDX format on the other side (using
different SBOM generators at different points in time). Package URLs (PURLs) are
extracted from both ends to determine SBOM true-positives (components correctly
reported), false-negatives (components missing in the SBOM) and
[recall](https://en.wikipedia.org/wiki/Precision_and_recall).  

Notes:
- The SBOM generators considered are [Eclipse jbom](https://github.com/eclipse/jbom/), [Syft](https://github.com/anchore/syft/), [Trivy](https://github.com/aquasecurity/trivy/) and the [CycloneDX Maven Plugin](https://github.com/CycloneDX/cyclonedx-maven-plugin).
- Per default, the script only considers Maven dependencies with scope `compile`
  and `runtime`.
- The evaluation relies on component PURLs only. Other identifiers such as the
simple component name or digest, where present, are not considered.

## Prerequisites

- Git
- Java and Maven (the required versions depend on the project analyzed)
- [jq v1.6](https://stedolan.github.io/jq/)
- SBOM generators `bin/jbom.jar`, `bin/syft` and `bin/trivy` (see the respective download page)

## Run the script

Details of the Maven project to be analyzed are specified through shell
variables in the header of the script.

The current values point to [Spring Boot
PetClinic](https://github.com/spring-petclinic/spring-petclinic-rest) (REST)
v2.6.2, which produces an executable JAR and which has also been published on
Docker Hub. 

Starting the script via `./eval-sboms.sh --dir pet` will create a new folder
`pet` into which the project will be cloned and where the SBOM generators will
be run at different lifecycle stages according to the following matrix (also see
`./eval-sboms.sh --help`):

```
Lifecycle Stage            | CycloneDX Maven Plugin | Eclipse jbom | Syft | Trivy
-------------------------- | ---------------------- | ------------ | ---- | -----
After git clone with dir   | x                      |              | x    | x    
After mvn package with JAR |                        | x            | x    |      
With Docker image          |                        |              | x    | x    
At JAR runtime             |                        | x            |      |     
```

The script output is structured into several steps, e.g., cloning the project or
packaging the Maven project, and most steps produce one or more files prefixed
with the respective step number. `2-exp-purls.txt`, for instance, contains the
PURLs that will be expected in the generated SBOMs and which are used to
determine TP, FN and recall.

The commands used to invoke the SBOM generators are printed to the console,
prefixed with `+ `, in order to re-run single generators, e.g., to reproduce
single SBOMs or change configuration options. 

Here some sample output until step 3:

```
Check prerequisites: OK

1) Clone repo https://github.com/spring-petclinic/spring-petclinic-rest into folder pet
   Checkout commit ee236caf798dde6ead7ab0726fb1cea96ca398ae

2) Resolve dependencies declared in pet/./pom.xml

   Raw text output in pet/2-deptree.txt contains the following deps:
    -  99 compile
    -   6 runtime
    -   0 provided
    -   0 system
    -  26 test

   SBOM true-positives (TP), false-negatives (FN) and recall will be computed for deps with scope(s): compile,runtime
   pet/2-exp-purls.txt - 105 PURLs have such scope(s)

3) Create SBOMs with directory

   Invoke CycloneDX (cycl): OK
   + mvn -DoutputFormat=json -DoutputDirectory=pet -DoutputName=3-git-cycl-sbom org.cyclonedx:cyclonedx-maven-plugin:2.7.5:makeBom -f pet/pom.xml > pet/3-git-cycl-sbom.log 2>&1
   pet/3-git-cycl-purls.txt - Contains 105 component PURLs in SBOM pet/3-git-cycl-sbom.json (TP = 105, FN =   0, recall = 1.00)
```

## DIY - Run script on other Maven projects

To scan other Maven projects, simply create a copy of the script and specify the following
variables in the script header:
```
repo=
commit=
name=
version=
image=                # Leave empty if there's no Docker image to scan
jar=
executable_jar=       # True if the JAR can be started with 'java -jar', false otherwise
prj_path="."          # Relative path from Git to folder with pom.xml
```

For example, the following can be used to scan the [OWASP
Webgoat](https://github.com/WebGoat/WebGoat) application, another Spring Boot
application published as Docker image:
```
repo=https://github.com/WebGoat/WebGoat.git
commit=3fd66ee9d94ae2673bff0867eeda5fadfd7a8dde
name=webgoat
version=2023.4
image=webgoat/webgoat:v2023.4
jar=$name-$version.jar
executable_jar=true
prj_path="."
```

Maven projects that do not use the default `project.build.directory` (target) or
whose JARs require additional system properties when started with `java -jar`
require further script adjustments.

## Background

The shell script extract sets of components from a Java/Maven project on one
side, and from generated SBOMs on the other side. Those sets will be stored in
`txt` files that are compared with `comm` to compute the accuracy of an SBOM in
regards to containing the "expected" components.

In the context of this script, we expect an SBOM to contain PURL identifiers for
all Maven compile and runtime dependencies (**where PURL namespace, name and
version correspond to the Maven groupId, artifactId and version**). This subset
of Maven dependencies is required at application runtime, and must be monitored
in regards to known vulnerabilities, which is today's primary SBOM use-case.

You can adjust `expected_mvn_scopes` if you want to consider other scopes.

The decision to focus on PURLs makes it possible to automate this comparison to
a greater extent. They are well-defined and created by all SBOM generators for
most of the reported components, which is not the case for digests or CPEs.

The `txt` files produced during SBOM generation can be easily used to identify
false-negatives, i.e. expected component PURLs not present in the generated
SBOMs. Examples:
- `comm -23 2-exp-purls.txt 3-git-triv-purls.txt` shows all Maven compile/runtime
  dependencies that are not found when running Trivy on the cloned repository.
- `comm -23 2-exp-purls.txt 6-img-syft-purls.txt` shows all Maven compile/runtime
  dependencies not found when running Syft on PetClinic's Docker image.

But what about false-positives? Unfortunately, there are multiple reasons why a
component with Maven PURL may "unexpectedly" show up in an SBOM, and it depends on
the context whether or not they are considered false-positives.

Cases where the SBOM generator wrongly determines the PURL namespace, name or
version for an expected compile/runtime dependency, can be considered
false-positives (there will also be a corresponding false-negative). Maven test
dependencies that appear with a CycloneDX scope other than "excluded" are also
considered false-positives.

The following cases, however, exemplify true-positives that can not easily be
spotted (or not at all) when considering compile/runtime dependencies in the
Maven dependency tree as ground truth:

- Maven PURLs for JDK libaries found in a Docker image.
- Re-bundled or re-packaged archives, identified on the basis of, e.g.,metadata
  or code found in a Java archive.
- Components belonging to application containers, some of which may correspond
  to system/provided dependencies of the Maven project.

The following command exemplifies how to find SBOM components that are not among
the expected ones:
- `comm -13 2-exp-purls.txt 7-run-jbom-purls.txt` shows components of the
  runtime SBOM produced by jbom that are not part of the expected dependencies.

The reasons to cram the whole data collection into one bash script were to
support comprehensibility (by not requiring any other programs and libraries)
and extensibility.
