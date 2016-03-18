#!/bin/bash

version="1.0.2"
staging_url="https://oss.sonatype.org/service/local/staging/deploy/maven2/"
#staging_url=file:/Users/rainer/tmp/test-local-repo
repositoryId="ossrh"
module="digidoc4j"

# Starting GPG agent to store GPG passphrase so we wouldn't have to enter the passphrase every time
eval $(gpg-agent --daemon --no-grab)
export GPG_TTY=$(tty)
export GPG_AGENT_INFO

artifact="dist/$module-$version"
echo "Deploying $artifact"
mvn gpg:sign-and-deploy-file -DpomFile=$artifact.pom -Dfile=$artifact.jar -Durl=$staging_url -DrepositoryId=$repositoryId
mvn gpg:sign-and-deploy-file -DpomFile=$artifact.pom -Dfile=$artifact-sources.jar -Dclassifier=sources -Durl=$staging_url -DrepositoryId=$repositoryId
mvn gpg:sign-and-deploy-file -DpomFile=$artifact.pom -Dfile=$artifact-javadoc.jar -Dclassifier=javadoc -Durl=$staging_url -DrepositoryId=$repositoryId

echo "Finished deployment"

killall gpg-agent