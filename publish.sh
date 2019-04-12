#!/bin/bash

version="3.1.1"
staging_url="https://oss.sonatype.org/service/local/staging/deploy/maven2/"
repositoryId="ossrh"

# Starting GPG agent to store GPG passphrase so we wouldn't have to enter the passphrase every time
eval $(gpg-agent --daemon --no-grab)
export GPG_TTY=$(tty)
export GPG_AGENT_INFO

# Deploy parent POM
mvn gpg:sign-and-deploy-file -DpomFile=pom.xml -Dfile=pom.xml -Durl=$staging_url -DrepositoryId=$repositoryId

# Deploy each sub module artifacts
for submodule in ddoc4j digidoc4j
do
	echo "Deploying submodule $submodule"
    cd $submodule
    artifact="target/$submodule-$version"
    mvn gpg:sign-and-deploy-file -DpomFile=pom.xml -Dfile=$artifact.jar -Durl=$staging_url -DrepositoryId=$repositoryId
    mvn gpg:sign-and-deploy-file -DpomFile=pom.xml -Dfile=$artifact-sources.jar -Dclassifier=sources -Durl=$staging_url -DrepositoryId=$repositoryId
    mvn gpg:sign-and-deploy-file -DpomFile=pom.xml -Dfile=$artifact-javadoc.jar -Dclassifier=javadoc -Durl=$staging_url -DrepositoryId=$repositoryId
    cd ..
    echo "Finished $submodule deployment"
done

killall gpg-agent
