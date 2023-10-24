#!/bin/bash

source /root/jucify_venv/bin/activate
cd $(dirname $0)/scripts

# ./main.sh -f /benchApps/getter_imei.apk -t -p /platforms
# must use full path
./main.sh $*
# result files: APK_NAME/ APK_NAME_result/ APK_NAME.native.log APK_NAME.flow.log
