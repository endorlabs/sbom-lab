#!/usr/bin/env bash

repo=https://github.com/spring-petclinic/spring-petclinic-rest
commit=ee236caf798dde6ead7ab0726fb1cea96ca398ae     # Commit or tag to check out
name=spring-petclinic-rest
version=2.6.2
image=springcommunity/spring-petclinic-rest:2.6.2   # Leave empty if there's no Docker image to scan
jar=$name-$version.jar
executable_jar=true                                 # True if the JAR can be started with 'java -jar', false otherwise
prj_path="."                                        # Relative path from Git to folder with pom.xml

# Requirements:
# - Git, Maven, Java, jq, and the following SBOM generators in subdir bin/
# - https://github.com/eclipse/jbom/releases/
# - https://github.com/anchore/syft/releases/
# - https://github.com/aquasecurity/trivy/releases

RED="\e[1;31m"; GREEN="\e[1;32m"; WHITE="\e[1;37m"; RESET="\e[0m" # ANSI color codes, reset with --disable-color
expected_mvn_scopes=("compile" "runtime") # Scopes expected in generated SBOMs, used to determine TP, FN and recall
scopes_text=$(IFS=, ; echo "${expected_mvn_scopes[*]}")

function help() {
    printf -- "Usage: %s\n\n" "$0"
    printf -- "Clones a Git repo with a Maven project and runs 4 SBOM generators at\n"
    printf -- "4 different lifecycle stages. The Git repo and other settings can be\n"
    printf -- "adjusted in the header of the script.\n\n"
    printf -- "Flags:\n"
    printf -- "   -h, --help            Print this help text\n"
    printf -- "   -d, --dir             Directory into which the repo will be cloned\n"
    printf -- "       --disable-color   Disable ANSI colors in console output\n"
    printf -- "       --keep-git        Keep the repo's .git folder\n"
    printf -- "   -s, --sbom            Extra SBOM in CylconeDX format to evaluate,\n"
    printf -- "                         e.g., downloaded from a commercial generator\n\n" 
    printf -- "Lifecycle Stage            | CycloneDX Maven Plugin | Eclipse jbom | Syft | Trivy\n"
    printf -- "-------------------------- | ---------------------- | ------------ | ---- | -----\n"
    printf -- "After git clone with dir   | x                      |              | x    | x    \n"
    printf -- "After mvn package with JAR |                        | x            | x    |      \n"
    printf -- "With Docker image          |                        |              | x    | x    \n"
    printf -- "At JAR runtime             |                        | x            |      |      \n\n"
    printf -- "Each SBOM generation produces 3 files:\n"
    printf -- "- SBOM in CycloneDX format: <step>-<stage>-<tool>-sbom.json\n"
    printf -- "- Text file with all PURLS: <step>-<stage>-<tool>-purls.txt\n"
    printf -- "- Console log: <step>-<stage>-<tool>-sbom.log\n\n"
    printf -- "Each SBOM is compared with the Maven project's dependencies to establish\n"
    printf -- "true-positive (TP) SBOM components, false-negatives (FN) and SBOM recall.\n"
    printf -- "${WHITE}Important${RESET}: This happens only on the basis of PURLs obtained from the JSON\n"
    printf    "SBOM and PURLs constructed from Maven deps with scopes: %s\n\n" "$scopes_text"
    printf -- "Create a copy of this script and adjust lines 3-10 to scan other projects.\n\n"
    printf -- "Feedback \xF0\x9F\x91\x89 https://github.com/endorlabs/sbom-lab \n"
}

# Parse command line args
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --keep-git)
        keep_git="true"
        shift
        ;;
        --disable-color)
        RED=""; GREEN=""; WHITE=""; RESET=""
        shift
        ;;
        -h|--help)
        help
        exit 0
        ;;
        -d|--dir)
        dir="$2"
        shift
        shift
        ;;
        -s|--sbom)
        other_sbom="$2"
        shift
        shift
        ;;
        *)
        echo "Unknown option: $1"
        help
        exit 1
        ;;
    esac
done

# Check --dir arg
if [ -z "$dir" ]; then
    help
    exit 1
fi
if [ -d "$dir" ]; then
    printf "${RED}ERROR${RESET}: Directory ${WHITE}%s${RESET} already exists\n" "$dir"
    exit 1
fi

exp_count=0 # No. expected components. Set in 2_deptree(), used to compute recall in find_purls_in_json_sbom()
tgt_path="$dir/$prj_path/target"
pom="$dir/$prj_path/pom.xml"

# Checks whether ./bin/jbom.jar, syft and trivy exist.
function check_prerequisites() {
    ok=true
    printf "Check prerequisites:"
    if [ ! -f "./bin/jbom.jar" ]; then
        printf "\n   Eclipse jbom - Download JAR from ${WHITE}%s${RESET} to ${WHITE}%s${RESET}" "https://github.com/eclipse/jbom/releases" "./bin/jbom.jar"
        ok=false
    fi
    if [ ! -f "./bin/syft" ]; then
        printf "\n   Syft - Download and extract binary from ${WHITE}%s${RESET} to ${WHITE}%s${RESET}" "https://github.com/anchore/syft/releases" "./bin/syft"
        ok=false
    fi
    if [ ! -f "./bin/trivy" ]; then
        printf "\n   Trivy - Download and extract binary from ${WHITE}%s${RESET} to ${WHITE}%s${RESET}" "https://github.com/aquasecurity/trivy/releases" "./bin/trivy"
        ok=false
    fi
    if ! jq --help > /dev/null 2>&1; then
        printf "\n   jq - Install from ${WHITE}%s${RESET}" "https://stedolan.github.io/jq/"
        ok=false
    fi
    if [ "$ok" == "true" ]; then
        printf " ${GREEN}OK${RESET}\n"
    else
        printf "\n${RED}ERROR${RESET}: One or more prerequisites are not met\n"; exit 1;
    fi
}

# Clone and checkout of Git $repo and $commit into --dir.
function 1_clone() {
    cwd=$(pwd)
    printf "\n1) Clone repo ${WHITE}%s${RESET} into folder ${WHITE}%s${RESET}\n" $repo "$dir"
    git clone $repo "$dir" -q || { printf "   ${RED}ERROR${RESET}: Cannot clone repo\n"; exit 1; }
    cd "$dir" || exit
    printf "   Checkout commit ${WHITE}%s${RESET}\n" $commit
    git checkout $commit -q || { printf "   ${RED}ERROR${RESET}: Cannot checkout commit\n"; exit 1; }
    if [ "$keep_git" != "true" ]; then
        rm -rf .git
    fi
    cd "$cwd" || exit
}

# Saves the raw output of "mvn dependency:tree" in "2-deptree.txt". Extracts all
# dependencies with $expected_mvn_scopes and saves corresponding PURLs in
# "2-exp-purls.txt" (sorted).
function 2_deptree() {
    printf "\n2) Resolve dependencies declared in ${WHITE}%s${RESET}\n" "$pom"
    mvn -q dependency:tree -DoutputType=text -DoutputFile=2-deptree.txt -f "$pom" || { printf "   ${RED}ERROR${RESET}: mvn dependency:tree -pl ${WHITE}%s${RESET} failed\n" "$pom"; exit 1; }
    mv "$dir/$prj_path/2-deptree.txt" "$dir/2-deptree.txt"

    # Info
    printf "\n   Raw text output in ${WHITE}%s${RESET} contains the following deps:\n" "$dir/2-deptree.txt"
    all_mvn_scopes=("compile" "runtime" "provided" "system" "test")
    for scope in "${all_mvn_scopes[@]}"; do
        count=$(grep ":$scope" "$dir/2-deptree.txt" -c)
        printf "    - ${WHITE}%3d %s${RESET}\n" "$count" "$scope"
    done
    
    # Write deps with expected scopes into "2-exp-purls.txt" (delete existing file beforehand).
    if [ -f "$dir/2-exp-purls.txt" ]; then
        rm "$dir/2-exp-purls.txt"
    fi
    for scope in "${expected_mvn_scopes[@]}" ; do
        # Make sure to catch deps with and without Maven classifier, as they have a different number of colon-separated elements, e.g.,
        # [INFO] +- org.eclipse.steady:shared:jar:3.2.6-SNAPSHOT:compile
        # [INFO] +- org.eclipse.steady:shared:jar:tests:3.2.6-SNAPSHOT:test
        sed -n "s/^.*- \([^:]*\):\([^:]*\):[^:]*:\([^:]*\):$(echo "$scope")$/pkg:maven\/\1\/\2@\3/p"       "$dir/2-deptree.txt" >> "$dir/2-exp-purls.txt"
        sed -n "s/^.*- \([^:]*\):\([^:]*\):[^:]*:[^:]*:\([^:]*\):$(echo "$scope")$/pkg:maven\/\1\/\2@\3/p" "$dir/2-deptree.txt" >> "$dir/2-exp-purls.txt"
    done
    sort -o "$dir/2-exp-purls.txt" "$dir/2-exp-purls.txt"

    # Info
    exp_count=$(wc -l < "$dir/2-exp-purls.txt")
    printf "\n   SBOM true-positives (TP), false-negatives (FN) and recall will be computed for deps with scope(s): ${WHITE}%s${RESET}\n" "$scopes_text"
    printf "   ${WHITE}%s${RESET} - ${WHITE}%d${RESET} PURLs have such scope(s)\n" "$dir/2-exp-purls.txt" "$exp_count"
}

# Searches for all PURLs in CycloneDX SBOM $1 and writes them to $2 (sorted).
# Only components with CycloneDX scopes "required" and "optional" are considered
# (or without scope). Potential PURL qualifiers (?) and subpaths (#) are
# removed. Also computes number of true-positives, false-negatives and recall.
function find_purls_in_json_sbom() {
    less "$1" | jq -r 'select(.components != null)
        | .components[]
        | select(.purl != null)
        | select(.scope == null or .scope == "required" or .scope == "optional") 
        | .purl
        | split("?")[0] | split("#")[0]' > "$2"
    sort -o "$2" "$2"
    count=$(wc -l < "$2")
    
    # TP and FN with regard to expected components
    tp_count=$(comm -12 "$dir/2-exp-purls.txt" "$2" | wc -l)
    fn_count=$(comm -23 "$dir/2-exp-purls.txt" "$2" | wc -l)
    recall=$(echo "$tp_count / $exp_count" | bc -l)
    printf "   ${WHITE}%s${RESET} - Contains ${WHITE}%3d${RESET} component PURLs in SBOM ${WHITE}%s${RESET} (TP = ${GREEN}%3d${RESET}, FN = ${RED}%3d${RESET}, recall = ${WHITE}%0.2f${RESET})\n" "$2" "$count" "$1" "$tp_count" "$fn_count" "$recall"

    # Make sure numbers add up
    [ $(($tp_count+$fn_count)) == $exp_count ] || { printf "   ${RED}ERROR${RESET}: ${WHITE}%d${RESET} TP + ${WHITE}%d${RESET} FN are not equal to ${WHITE}%d${RESET} expected deps\n" "$tp_count" "$fn_count" "$exp_count" ; exit 1; } 
}

# Runs tool $1 through "eval $2".
function run_sbom_generator() {
    printf "\n   Invoke ${WHITE}%s${RESET}: " "$1"
    if eval "$2"; then
        printf "${GREEN}OK${RESET}\n"
    else
        printf "${RED}ERROR${RESET} - check log and/or reproduce with\n"
    fi
    printf "   + ${WHITE}%s${RESET}\n" "$2"
}

# Runs CycloneDX Maven plugin, syft and trivy. Produces 3-git-$tool-sbom.json, 3-git-$tool-sbom.log, 3-git-$tool-purl.txt 
function 3_sbom_after_clone() {
    printf "\n3) Create SBOMs with directory\n"

    # CycloneDX
    run_sbom_generator "CycloneDX (cycl)" "mvn -DoutputFormat=json -DoutputDirectory=$dir -DoutputName=3-git-cycl-sbom org.cyclonedx:cyclonedx-maven-plugin:2.7.5:makeBom -f $dir/pom.xml > $dir/3-git-cycl-sbom.log 2>&1"
    mv ""$tgt_path"/3-git-cycl-sbom.json" "$dir"
    find_purls_in_json_sbom "$dir/3-git-cycl-sbom.json" "$dir/3-git-cycl-purls.txt"

    # jbom (disabled, since it requires JARs)
    # java -jar generators/jbom-1.2.1.jar --dir="$dir" --outputDir="$dir"
    # mv "$dir/jbom-$dir.json" "$dir/3-git-jbom-sbom.json"

    # Syft
    run_sbom_generator "Syft" "./bin/syft packages dir:$dir --file $dir/3-git-syft-sbom.json -o cyclonedx-json > $dir/3-git-syft-sbom.log 2>&1"
    find_purls_in_json_sbom "$dir/3-git-syft-sbom.json" "$dir/3-git-syft-purls.txt"

    # Trivy (offers plenty of options related to caching and connectivity, e.g., --skip-java-db-update, --offline-scan or --cache-dir)
    run_sbom_generator "Trivy (triv)" "./bin/trivy fs --debug --format cyclonedx --output $dir/3-git-triv-sbom.json $dir > $dir/3-git-triv-sbom.log 2>&1"
    find_purls_in_json_sbom "$dir/3-git-triv-sbom.json" "$dir/3-git-triv-purls.txt"
}

# Runs "mvn -DskipTests package -f $dir/pom.xml" and produces JAR and 4-jartf.txt
function 4_package() {
    printf "\n4) Call 'mvn package' to create JAR\n"
    if [ ! -f "$tgt_path/$jar" ]; then
        mvn -DskipTests package -f "$pom" > "$dir/4-pkg.log" 2>&1 || { printf "   ${RED}ERROR${RESET}: 'mvn package' failed\n"; exit 1; }
    fi
    jar tf "$tgt_path/$jar" > "$dir/4-jartf.txt" || { printf "   ${RED}ERROR${RESET}: jar tf ${WHITE}%s${RESET} failed, check value of variable 'jar'\n" "$tgt_path/$jar"; exit 1; }
    count=$(grep -E "BOOT-INF/lib/.+" "$dir/4-jartf.txt" -c)

    printf "\n   Created JAR ${WHITE}%s${RESET}\n" "$tgt_path/$jar"
    printf "   ${WHITE}%s${RESET} - Number of files in BOOT-INF/lib = ${WHITE}%d${RESET}\n" "$dir/4-jartf.txt" "$count"
}

# Runs jbom and syft on target/$jar. Produces: 5-pkg-$tool-sbom.json, 5-pkg-$tool-sbom.log, 5-pkg-$tool-purls.txt
function 5_sbom_after_package() {
    printf "\n5) Create SBOMs with JAR\n"
    
    # jbom
    run_sbom_generator "jbom" "java -jar ./bin//jbom.jar --file=$tgt_path/$jar --outputDir=$dir > $dir/5-pkg-jbom-sbom.log 2>&1"
    mv "$dir/jbom-$name-$version.json" "$dir/5-pkg-jbom-sbom.json"
    find_purls_in_json_sbom "$dir/5-pkg-jbom-sbom.json" "$dir/5-pkg-jbom-purls.txt"

    # Syft
    run_sbom_generator "Syft" "./bin/syft packages file:$tgt_path/$jar --file $dir/5-pkg-syft-sbom.json -o cyclonedx-json > $dir/5-pkg-syft-sbom.log 2>&1"
    find_purls_in_json_sbom "$dir/5-pkg-syft-sbom.json" "$dir/5-pkg-syft-purls.txt"

    # Trivy (disabled, because fs scans do not consider JARs, see https://aquasecurity.github.io/trivy/v0.37/docs/vulnerability/detection/language/)
    #./bin/trivy fs --format cyclonedx --output $dir/5-pkg-triv-sbom.json $tgt_path/$jar
}

# Runs syft and trivy on Docker $image. Produces: 6-img-$tool-sbom.json, 6-img-$tool-sbom.log, 6-img-$tool-purls.txt
function 6_sbom_with_image() {
    if [ -z "$image" ]; then
        printf "\n6) Skip creating SBOMs with Docker image\n"
    else
        printf "\n6) Create SBOMs with Docker image ${WHITE}%s${RESET}\n" $image

        # Syft
        run_sbom_generator "Syft" "./bin/syft packages $image --file $dir/6-img-syft-sbom.json -o cyclonedx-json > $dir/6-img-syft-sbom.log 2>&1"
        find_purls_in_json_sbom "$dir/6-img-syft-sbom.json" "$dir/6-img-syft-purls.txt"

        # Trivy (--cache-dir ./bin/trivy-cache)
        run_sbom_generator "Trivy (triv)" "./bin/trivy image --debug --format cyclonedx --output $dir/6-img-triv-sbom.json $image > $dir/6-img-triv-sbom.log 2>&1"
        find_purls_in_json_sbom "$dir/6-img-triv-sbom.json" "$dir/6-img-triv-purls.txt"
    fi
}

# Runs "java -jar target/$jar" and attaches jbom to the pid. Produces: 7-run-$tool-sbom.json, 7-run-$tool-sbom.log, 7-run-$tool-purls.txt
function 7_sbom_at_runtime() {
    if [ ! "$executable_jar" == "true" ]; then
        printf "\n7) Skip creating runtime SBOMs\n"
    else
        printf "\n7) Create runtime SBOMs\n"

        # jbom
        java -jar "$tgt_path/$jar" > "$dir/7-run-jbom-sbom.log" 2>&1 &
        pid=$!
        runtime_wait=10
        printf "\n   Started executable JAR ${WHITE}%s${RESET} with pid ${WHITE}%d${RESET}, waiting %d secs before attaching jbom...\n" "$tgt_path/$jar" $pid $runtime_wait
        sleep $runtime_wait

        # Check if process runs
        if ps -p "$pid" > /dev/null; then    
            java -jar ./bin/jbom.jar --pid=$pid --outputDir="$dir" > /dev/null
            mv "$dir/jbom-$pid.json" "$dir/7-run-jbom-sbom.json"
            kill $pid > /dev/null 2>&1 || { printf "   ${RED}ERROR${RESET}: Unable to kill pid ${WHITE}%d${RESET}, kill manually\n" $pid; }
            find_purls_in_json_sbom "$dir/7-run-jbom-sbom.json" "$dir/7-run-jbom-purls.txt"
        else
            printf "   ${RED}ERROR${RESET}: Failed to start JAR, see ${WHITE}%s${RESET}\n" "$dir/7-run-jbom-sbom.log"
        fi
    fi
}

# Computes TP, FN and recall for an SBOM provided with --sbom.
function 8_sbom_arg() {
    if [ ! -f "$other_sbom" ]; then
        printf "\n8) No SBOM provided with --sbom\n"
    else
        printf "\n8) Evaluate --sbom ${WHITE}%s${RESET}\n" "$other_sbom"
        cp "$other_sbom" "$dir/8-arg-othr-sbom.json"
        find_purls_in_json_sbom "$dir/8-arg-othr-sbom.json" "$dir/8-arg-othr-purls.txt"
    fi
}

check_prerequisites
1_clone
2_deptree
3_sbom_after_clone
4_package
5_sbom_after_package
6_sbom_with_image
7_sbom_at_runtime
8_sbom_arg
