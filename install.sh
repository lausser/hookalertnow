#! /bin/bash

pushd $(dirname $(readlink -f $0))
ansible-playbook hookalertnow_playbook.yml \
    -i localhost, -c local
popd
omd stop
omd config set PROMETHEUS on
omd config set ALERTMANAGER on
omd start
omd stop hookalertnow
