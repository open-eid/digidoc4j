#!/bin/sh
RELEASE_BUILD_DIR=release_build
JAVADOC_TMP_DIR=/tmp/javadoc
if [[ ! -f token ]]; then
    echo "Token file does not exist. Execution aborted."
    exit 1
fi
TOKEN=$(cat token)
export BUILD_NUMBER=0

if [[ -d  ${RELEASE_BUILD_DIR} ]]; then
    rm -rf ${RELEASE_BUILD_DIR}
fi
mkdir ${RELEASE_BUILD_DIR}
pushd ${RELEASE_BUILD_DIR}

git clone --recursive https://github.com/open-eid/digidoc4j
cd digidoc4j

VERSION=$(git tag -l public* --sort=version:refname | tail -1 | awk -F '-' '{print $2}')

git checkout tags/public-${VERSION}

IFS='. ' read -a version <<< ${VERSION}
if [[ $1 == "PRERELEASE" ]]; then
    FINAL_VERSION=${version[0]}"."${version[1]}"."${version[2]}
    PRERELEASE=true
else
    FINAL_VERSION=${version[0]}.${version[1]}.${version[2]}
    PRERELEASE=false
fi

echo "Starting to build...."
ant -q -f jenkins_build.xml sd-dss
ant -q all -Dlib.version=v${FINAL_VERSION}
echo "Build done!"

CREATE_RELEASE=$(printf '{"tag_name": "v%s","target_commitish": "master","name": "Release v%s","body": "### Release of version %s","draft": false,"prerelease": %s}' ${FINAL_VERSION} ${FINAL_VERSION} ${FINAL_VERSION} ${PRERELEASE})
RESPONSE=$(curl --data "${CREATE_RELEASE}" https://api.github.com/repos/open-eid/digidoc4j/releases?access_token=${TOKEN})
RELEASE_ID=$(echo ${RESPONSE} | sed -e 's/[{}]/''/g' | awk -F ', ' '{print $5}' | awk -F': ' '{print $2}')

re='^[0-9]+$'
if ! [[ $RELEASE_ID =~ $re ]] ; then
   echo "error: Not a correct id: $RELEASE_ID" >&2; exit 1
fi

echo "Uploading assets for release ${RELEASE_ID}... "
UPLOAD_URL="https://uploads.github.com/repos/open-eid/digidoc4j/releases/${RELEASE_ID}/assets"

echo name=digidoc4j-v${FINAL_VERSION}.0-javadoc.jar --data-binary @dist/digidoc4j-v${FINAL_VERSION}.0-javadoc.jar
curl --fail -s -S -H "Authorization: token ${TOKEN}" -H "Content-Type: application/zip" -X POST ${UPLOAD_URL}?name=digidoc4j-v${FINAL_VERSION}.0-javadoc.jar --data-binary @dist/digidoc4j-v${FINAL_VERSION}.0-javadoc.jar
curl --fail -s -S -H "Authorization: token ${TOKEN}" -H "Content-Type: application/zip" -X POST ${UPLOAD_URL}?name=digidoc4j-v${FINAL_VERSION}.0.jar --data-binary @dist/digidoc4j-v${FINAL_VERSION}.0.jar
curl --fail -s -S -H "Authorization: token ${TOKEN}" -H "Content-Type: application/zip" -X POST ${UPLOAD_URL}?name=digidoc4j-library-v${FINAL_VERSION}.0.zip --data-binary @dist/digidoc4j-library-v${FINAL_VERSION}.0.zip
curl --fail -s -S -H "Authorization: token ${TOKEN}" -H "Content-Type: application/zip" -X POST ${UPLOAD_URL}?name=digidoc4j-util-v${FINAL_VERSION}.0.zip --data-binary @dist/digidoc4j-util-v${FINAL_VERSION}.0.zip

if [[ -d  ${JAVADOC_TMP_DIR} ]]; then
    rm -rf ${JAVADOC_TMP_DIR}
fi
mkdir ${JAVADOC_TMP_DIR}
cp -r javadoc/ ${JAVADOC_TMP_DIR}

git checkout --orphan gh-pages
git reset --hard
rm -rf *
cp -r ${JAVADOC_TMP_DIR}/ .
git add $(git ls-files -o --exclude-standard)
git commit -m"javadoc"
git push --set-upstream origin gh-pages

popd

echo "Release for GitHub created"