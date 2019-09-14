#########################################################################
## 
## unpacking saved docker image
## docker save -o out.tgz private.repo.org.com/someImage

echo $PWD
export JOBPATH=$PWD
dirs=($(find . -type d))
for dir in "${dirs[@]}"; do
  if [ $dir = $JOBPATH ]; then
    echo "skip parent directory"
  else
    cd "$dir"
    echo $PWD
	tar -xvf layer.tar
	#strings * 
    cd $JOBPATH
  fi
done


echo $PWD
export JOBPATH=$PWD
dirs=($(find . -type d))
for dir in "${dirs[@]}"; do
  if [ $dir = $JOBPATH ]; then
    echo "skip parent directory"
  else
    cd "$dir"
	echo "****************************************" >> $JOBPATH/log.text
    echo $PWD >> $JOBPATH/log.text
	echo "****************************************" >> $JOBPATH/log.text
	strings * | $JOBPATH/script.py >> $JOBPATH/log.text
	echo "#########################################" >> $JOBPATH/log.text
	echo "                                         " >> $JOBPATH/log.text
    cd $JOBPATH
  fi
done

###########################################################################
##
## python search script
## REF:https://github.com/dxa4481/truffleHog/blob/dev/scripts/searchOrg.py 

#!/usr/bin/env python
#import requests
#from truffleHog import truffleHog
import re
#from json import loads, dumps
import os
import sys

rules = {
    "Slack Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "SSH (OPENSSH) private key": "-----BEGIN OPENSSH PRIVATE KEY-----",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Facebook Oauth": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]",
    "Twitter Oauth": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]",
    "GitHub": "[g|G][i|I][t|T][h|H][u|U][b|B].{0,30}['\"\\s][0-9a-zA-Z]{35,40}['\"\\s]",
    "Google Oauth": "(\"client_secret\":\"[a-zA-Z0-9-_]{24}\")",
    "AWS API Key": "AKIA[0-9A-Z]{16}",
    "Heroku API Key": "[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Generic Secret": "[s|S][e|E][c|C][r|R][e|E][t|T].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]",
    "Generic API Key": "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]",
    "Slack Webhook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Google (GCP) Service-account": "\"type\": \"service_account\"",
    "Twilio API Key": "SK[a-z0-9]{32}",
    "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
}

for key in rules:
    rules[key] = re.compile(rules[key])
	


def regex_check(textblob, custom_regexes={}):
    if custom_regexes:
        secret_regexes = custom_regexes
    else:
        secret_regexes = regexes
    regex_matches = []
    for key in secret_regexes:
        found_strings = secret_regexes[key].findall(textblob)
        for found_string in found_strings:
            found_diff = textblob.replace(textblob, found_string)
        if found_strings:
            foundRegex = {}
            #foundRegex['date'] = commit_time
            #foundRegex['path'] = blob.b_path if blob.b_path else blob.a_path
            #foundRegex['branch'] = branch_name
            #foundRegex['commit'] = prev_commit.message
            #foundRegex['diff'] = blob.diff.decode('utf-8', errors='replace')
            foundRegex['stringsFound'] = found_strings
            #foundRegex['printDiff'] = found_diff
            foundRegex['reason'] = key
            #foundRegex['commitHash'] = prev_commit.hexsha
            regex_matches.append(foundRegex)
    return regex_matches

data = sys.stdin.read()
matches = regex_check(data, rules)

if matches > 0:
  for p in matches:
    print(p)
