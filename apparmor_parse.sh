#!/bin/sh

##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2024 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

Apparmor_defaults="/etc/apparmor/apparmor_defaults"
Apparmor_blocklist="/opt/secure/Apparmor_blocklist"
PROFILES_DIR="/etc/apparmor.d/"
PARSER="/sbin/apparmor_parser"
SYSFS_AA_PATH="/sys/kernel/security/apparmor/profiles"
RDKLOGS="/opt/logs/startup_stdout_log.txt"

if [ -f /lib/rdk/apparmor_utils.sh ]; then
    source /lib/rdk/apparmor_utils.sh
fi

if [ -f /lib/rdk/t2Shared_api.sh ]; then
    source /lib/rdk/t2Shared_api.sh
fi

if [ ! -f $Apparmor_blocklist ]; then
    touch $Apparmor_blocklist
fi

complain_list=()
enforce_list=()
unconfined_list=()
other_list=()

while read line; do
        mode=`echo $line | cut -d ":" -f 2`
        process=`echo $line | cut -d ":" -f 1`
        profile=`ls -ltr $PROFILES_DIR | grep -w $process | awk '{print $9}'`
        if [ ! -z $profile ]; then
	     blocklist_process=`grep -w $process $Apparmor_blocklist`
	     blocklist_mode=`echo $blocklist_process | awk -F ":" '{print $2}'`
	     if [ "$mode" == "enforce" ]; then
                     if [ "$blocklist_mode" == "complain" ]; then
                             complain_list+=("$PROFILES_DIR/$profile")
                     elif [ "$blocklist_mode" != "disable" ]; then
                             enforce_list+=("$PROFILES_DIR/$profile")
                     elif [ "$blocklist_mode" == "disable" ]; then
                           if [ "$process" != "global" ]; then
                           unconfined_list+=("$PROFILES_UNCONFINED_DIR/$profile")
                           fi
                     fi
             elif [ "$mode" == "complain" ] && [ "$blocklist_mode" != "disable" ]; then
                 other_list+=("$PROFILES_DIR/$profile")
             fi
        fi
done<$Apparmor_defaults
if [[ ${#complain_list[@]} -gt 0 ]]; then
    joined_string=$(IFS=" "; echo "${complain_list[*]}")
    apparmor_parser -rWC $joined_string
fi

if [[ ${#enforce_list[@]} -gt 0 ]]; then
    joined_string=$(IFS=" "; echo "${enforce_list[*]}")
    apparmor_parser -rW $joined_string
fi

if [[ ${#unconfined_list[@]} -gt 0 ]]; then
    joined_string=$(IFS=" "; echo "${unconfined_list[*]}")
    apparmor_parser -rWC $joined_string
fi

if [[ ${#other_list[@]} -gt 0 ]]; then
    joined_string=$(IFS=" "; echo "${other_list[*]}")
    apparmor_parser -rWC $joined_string
fi

if type systemd_apparmor; then
    systemd_apparmor
fi

list=`cat $SYSFS_AA_PATH | grep complain | awk '{print $1}' | tr '\n'  ','`
cnt=`cat $SYSFS_AA_PATH | grep complain | wc -l`
if [ ! -z "$list" ]; then
     echo "List of profiles in Apparmor-complain mode:$cnt : $list" >> $RDKLOGS
     t2ValNotify "APPARMOR_C_split:" "$cnt,$list"
fi

list=`cat $SYSFS_AA_PATH | grep enforce | awk '{print $1}' | tr '\n'  ','`
cnt=`cat $SYSFS_AA_PATH | grep enforce | wc -l`
if [ ! -z "$list" ]; then
     echo "List of profiles in Apparmor-enforce mode:$cnt : $list"  >> $RDKLOGS
     t2ValNotify "APPARMOR_E_split:" "$cnt,$list"
fi

if type apparmor_telemetry; then
    apparmor_telemetry
fi
