NETFLIX_USER=${NETFLIX_USER:-$(git config user.email | cut -f 1 -d '@')}

function getDevAgentIP() {
  metatron curl -a sonar "https://api.sonar.prod.netflix.net:7004/api/v2/Nodes?Term=spinnaker:stack:dev${NETFLIX_USER}cell001&App=titusagent" | jq -r .Nodes[0].Address
}

