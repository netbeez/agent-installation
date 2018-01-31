#!/bin/bash

# Netbeez
# Sets an Agent up to communicate with a Dashboard
# Agent -> request config -> central server -> config -> Agent
# find <<<MAIN>>> at the bottom of the file



#########################
# BLOCK: IMPORT ENV VARS HERE 
#########################



#########################
# BLOCK: ENV SETTINGS ###
#########################
set -e                      # exit all shells if script fails
set -u                      # exit script if uninitialized variable is used
set -o pipefail             # exit script if anything fails in pipe
# set -x;                   # debug mode



#########################
# BLOCK: GLOBALS ########
#########################

declare -ra ARGS=("$@")

declare -r SCRATCH_DIRECTORY="$(mktemp -d)"


declare -r PROGRAM="${0}"
declare -r LOG_FILE="/tmp/agent_setup.log"
declare -r UNIQUE_LOG_FILE="${LOG_FILE}.$(date +%s)"
declare -r BLACKLIST_FILE="/etc/modprobe.d/raspi-blacklist.conf"
declare -r BLACKLIST_FILE_BAK="/etc/modprobe.d/raspi-blacklist.conf.BAK"
declare -r DISABLED_WIRELESS_WRAPPER_STRING="# ############################ WRITTEN BY NETBEEZ agent_setup.sh"

  
# config directory and files
declare -r CONFIG_FOLDER="/etc/netbeez"           
declare -r CONFIG_FILE="netbeez-agent.conf"       
declare -r AGENT_PEM_FILE="netbeez-agent.pem"     
declare -r URL="https://ims.netbeez.net"  
declare -r END_POINT="apis/v1/agent_setup"
declare -r IMS_URL="${URL}/${END_POINT}"

CALL_DIR="$(pwd)"; declare -r CALL_DIR
CALL_PATH="${CALL_DIR}/${0}"; declare -r CALL_PATH
SCRIPT_NAME="$(basename "${CALL_PATH}")"; declare -r SCRIPT_NAME 


# PARSE PARAMS
function initialize_input(){
    log_func "${FUNCNAME[0]}"

    local -r args="${@}"

    log "INPUT/ARGUMENTS GIVEN: ${args}"

    local secret=""
    local is_secret="false"
    local is_dev="false"
    local is_interface_setup="false"
    local is_help="false"


    local -r opts=$(getopt -o dish --long ,secret:,modify-interface,dev,help -- ${args})
    eval set -- "${opts}"
    while true ; do
        case "${1}" in
            --secret) 
                is_secret="true"
                secret="${2}"
                shift 2
                ;;
            --dev)
                is_dev="true"
                shift 1
                ;;
            --modify-interface)
                is_interface_setup="true"
                shift 1
                ;;
            --help)
                is_help="true"
                shift 1
                ;;
            *)
                break
                ;;
        esac
    done;

    ###########################
    # CREATES GLOBAL VARIABLES
    readonly SECRET="${secret}"
    readonly IS_SECRET="${is_secret}"
    readonly IS_DEV="${is_dev}"
    readonly IS_INTERFACE_SETUP="${is_interface_setup}"
    readonly IS_HELP="${is_help}"
    # CREATES GLOBAL VARIABLES
    ###########################

    
}


#########################
# BLOCK: LOG FUNCTIONS  ########
#########################


function disk_log(){
    local -r msg="${1}"
    
    local -r unix_time="$(date +%s)"
    local -r full_msg="${unix_time} | ${SCRIPT_NAME} | ${msg}"

    echo "${full_msg}" >> "${LOG_FILE}"
    echo "${full_msg}" >> "${UNIQUE_LOG_FILE}"

}


function console_log(){
    local -r msg="${1}"
    local -r full_msg="${msg}"

    echo "${full_msg}" >&2
}


# base logging functoins
function log(){
    local -r msg="${1}"

    console_log "${msg}"
    disk_log "${msg}"
}


# prepends error to message
function error_log(){
    local -r msg="${1}"
    log "ERROR: ${msg}"
    exit 1
}


# prepends warning to message
function warning_log(){
    local -r msg="${1}"
    log "WARNING (1/2): ${msg}"
    log "WARNING (2/2): continuing"
}

function log_func(){
    local -r function_name="${1}"
    disk_log "${function_name}()"
}



# something blew up, this exits the script with some additional information
function error_log(){
    local -r msg="${1}"
    log "ERROR: EXITING SCRIPT: ${msg}"
    log "ERROR: EXITING SCRIPT: If you're stuck, contact support@netbeez.net"
    exit 1
}





#########################
# BLOCK: MISC FUNCTIONS ########
#########################

# displays usage information to the user for this script
function usage(){
    log_func "${FUNCNAME[0]}"
    # http://docopt.org
    log "----------------------------------------------------------------------------------------------------"
    log "Usage: ${PROGRAM} ( --secret=<key> | --modify-interface | --help )"
    log ""
    log "###### General Options "
    log "       --secret=<key>      the secret key given to you from Netbeez (usually via email)"
    log ""
    log "       --help              displays this usage page"
    log ""
    log "###### Raspberry Pi 3 **Only** Options "
    log "       --modify-interface  modifies the interface used (wireless or wired) without any additional setup"
    log ""
    log "###### More Information"
    log "       Agent Install       https://netbeez.zendesk.com/hc/en-us/articles/207989403-Install-NetBeez-agents-All-versions-"
    log "       Documentation       http://docopt.org"
    log "----------------------------------------------------------------------------------------------------"

}


function echo_count(){
    log_func "${FUNCNAME[0]}"

    local -r message="${1}"
    local -ri default_echo_count_to_print="1"
    local -ri number_of_spacers_to_print="${2:-${default_echo_count_to_print}}"
    local -i counter=0

    while [[  "${counter}" -lt "${number_of_spacers_to_print}" ]]; do
        echo "${message}"
        counter=counter+1
    done
}


function print_prompt_spacer(){
    log_func "${FUNCNAME[0]}"

    local -ri default_spacers_to_print="1"
    local -ri number_of_spacers_to_print="${1:-${default_spacers_to_print}}"
    local -i counter=0

    local -r prompt_spacer=">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"

    while [[  "${counter}" -lt "${number_of_spacers_to_print}" ]]; do
        echo "${prompt_spacer}"
        counter=counter+1
    done
}


function get_machine_architecture(){
    log_func "${FUNCNAME[0]}"

    local -r architecture="$(uname -m)"
    echo "${architecture}"
}



function print_is_software_agent(){
    log_func "${FUNCNAME[0]}"

    # is software agent?
    if [[ "$(is_software_agent)" == "true" ]]; then
        log "DETECTED AGENT TYPE: software agent"
    else
        log "DETECTED AGENT TYPE: **not** software agent"
    fi
}


function print_is_rpi_3(){
    log_func "${FUNCNAME[0]}"

    # is rpi3 3?
    if [[ "$(is_rpi_3_agent)" == "true" ]]; then
        log "DETECTED HARDWARE: Raspberry Pi 3 "
    else
        log "DETECTED HARDWARE: **not** Raspberry Pi 3"
    fi

}

function print_architecture(){
    log_func "${FUNCNAME[0]}"

    local -r architecture="$(get_machine_architecture)"
    log "DETECTED ARCHITECTURE: ${architecture}"
}


# print some info about this machine
function print_machine_information(){
    log_func "${FUNCNAME[0]}"

    clear

    echo_count '' 3

    log ">>>>>>>>>>>>>>>>>>> MACHINE INFORMATION "
    print_is_rpi_3
    print_is_software_agent
    print_architecture
    log ">>>>>>>>>>>>>>>>>>> MACHINE INFORMATION "

    echo_count '' 3
}


# checks for valid flags given to this script
function check_input(){
    log_func "${FUNCNAME[0]}"
    # checks parsed parameters
    # if any of the parameter options are 
    # > invalid a usage will be displayed
    local is_usage="false"

    # check if the user wants help
    if [[ "${IS_HELP}" == "true" ]]; then
        is_usage="true"

    elif [[ "${SECRET}" == "" && "${IS_INTERFACE_SETUP}" == "false" && "${IS_HELP}" == "false" ]]; then
        is_usage="true"

        echo_count '' 2
        log "ERROR: MUST give one of the following flags: --secret=<your_secret> *or* --modify-interface"
        echo_count '' 2

    elif [[ "${IS_INTERFACE_SETUP}" == "true" && "$(is_rpi_3_agent)" == "false" ]]; then
        is_usage="true"

        echo_count '' 2
        log "ERROR: CANNOT modify interface unless agent is a Raspberry Pi 3"
        echo_count '' 2
    fi


    # if usage is true, then display usage and exit
    if [[ "${is_usage}" == "true" ]]; then
        usage
        exit 1
    fi
}



#########################
# BLOCK: HARDWARE FUNCTIONS ###
#########################

# is this a "software" agent
function is_software_agent(){
    log_func "${FUNCNAME[0]}"

    local status="false"
    if [[ "$(is_image_agent)" != "true" ]]; then
        status="true"
    fi
    echo "${status}"
}


# is this an "image" agent
function is_image_agent(){
    log_func "${FUNCNAME[0]}"

    local -r image_agent_install_location="/usr/local/netbeez"

    local status="false"
    if [[ -d "${image_agent_install_location}" ]]; then
        status="true"
    fi
    echo "${status}"
}


# is this a raspberry pi 3 agent -- checks the mac oui and a model file present on the system
function is_rpi_3_agent(){
    log_func "${FUNCNAME[0]}"

    local -r rpi_3_model="Raspberry Pi 3"
    local -r model_file="/sys/firmware/devicetree/base/model"
    local -r address_file="/sys/class/net/wlan0/address"

    local status="false"

    if [[ -f "${address_file}" && -f "${model_file}" && $(cat "${model_file}" | grep "${rpi_3_model}") ]]; then
        status="true"
    fi
  
    echo "${status}"
}


# resters the agent processes based on agent type
function restart_agent_process(){
    log_func "${FUNCNAME[0]}"

    # Restart the agent process
    log "RESTARTING the Netbeez Agent process"

    if [[ "$(is_software_agent)" == "true" ]]; then
        sudo service netbeez-agent stop
        sleep 2
        sudo service netbeez-agent start
    else
        sudo service nbagent_prod stop
        sleep 2
        sudo service nbagent_prod start
    fi
}


# # compare the backed-up blacklist file with the current -- did it change
function is_blacklist_changed(){
    log_func "${FUNCNAME[0]}"

    local is_changed="false"

    local -r backup_blacklist_file="${BLACKLIST_FILE_BAK}"

    # if the backup files exists and diff the backup with the current
    if [[ -f "${backup_blacklist_file}" && $(diff "${BLACKLIST_FILE}" "${backup_blacklist_file}" ) ]]; then
        is_changed="true"
    fi

    echo "${is_changed}"
}



#########################
# BLOCK: SELF CONFIGURE ########
#########################
# the agent will configure itself from the ims
  
  # JSON: finds the value of a key
function find_value_by_key(){
    log_func "${FUNCNAME[0]}"

    # ###################
    # awk sets RS and FS so that 'k1:v1,...,kn:vn' is
    # "formatted" into a 2D table
    # then matches the key/$1 and prints value/$2
    # ###################
    local -r key="${1}"
    local -r json="${2}"

    local -r value=$(printf "${json}" \
        | awk -v key="\"$key\"" 'BEGIN{ RS=","; FS=":"; }; $1 ~ key {print $2}' \
        | sed 's/"//g')

    echo "${value}"
}



function write_to_disk(){
    log_func "${FUNCNAME[0]}"
    
    local -r data="${1}"
    local -r location="${2}"

    { # "try"
        log "writing to disk: initial attempt"
        sudo bash -c "echo \"${data}\" > \"${location}\""
    } || { # "catch"
        log "writing to disk: fallback 01"
        echo -n "${data}" > "${location}"
    } || { # "catch"
        log "writing to disk: fallback 02"
        echo "${data}" > "${location}"
    }
}



  # compares the md5 of a file on disk with a given md5 string
function is_valid_md5(){
    log_func "${FUNCNAME[0]}"
    local status="false"
    log "verifying the md5 of a file"
    # this verifies md5s for a file on disk
    # > create new md5: new_md5 = md5(file_on_disk)
    # > then compare: new_md5 == given_md5
    local -r check_me="${1}"
    local -r given_dirty_md5="${2}"
    local -r given_md5=$(echo "${given_dirty_md5}" | cut -d' ' -f1| sed -e 's/^[ \t]*//')
    local -r new_md5=$(md5sum "${check_me}" | cut -d' ' -f1|sed -e 's/^[ \t]*//')

    if [[ "${given_md5}" == "${new_md5}"  ]]; then
        status="true"
    fi

    echo "${status}"
}


  # writes the agent pem file (uses fallbacks and checks md5s)
function write_agent_pem(){
  log_func "${FUNCNAME[0]}"
    # 1. writes agent_pem to disk
    # 2. verifies the integrity of agent_pem
    # 3. moves agent_pem to proper location
    local -r netbeez_agent_pem="${1}"
    local -r netbeez_agent_pem_md5="${2}"

    local -r agent_pem_path="${CONFIG_FOLDER}/${AGENT_PEM_FILE}"

    log "VERIFYING key integrity"

    mkdir -p "${CONFIG_FOLDER}"

    ##############################################################
    ## FIRST TRY: WRITE AGENT PEM TO DISK AND VERIFY MD5
    write_to_disk "${netbeez_agent_pem}" "${agent_pem_path}"
    local is_okay=$(is_valid_md5 "${agent_pem_path}" "${netbeez_agent_pem_md5}")

    log "IMS MD5: ${netbeez_agent_pem_md5}"
    log "GENERATED MD5: $(md5sum ${agent_pem_path})"

    if [[ "${is_okay}" == "true" ]]; then
        log "INITIAL AGENT PEM WRITE SUCCEEDED"
    else
        error_log "THE key could not be verified"
    fi
}


  # requests config data from the ims
function request_config_data(){
    log_func "${FUNCNAME[0]}"

    log "making curl request to Netbeez at ${IMS_URL}"
    #get config data from the ims
    local -r response_json=$(curl \
                --silent \
                --request POST "${IMS_URL}" \
                --insecure \
                --data "secret=${SECRET}" \
                | sed 's/{\|}//g' )

    echo "${response_json}"
}


# checks the returned server values to see if they are valid (ie. not empty)
function check_result(){
    log_func "${FUNCNAME[0]}"
    # if any of parsed server values are empty, then something went wrong
    # if we have a message from the server then it at least got that far
    local -r result="${1}"
    local -r server_message="${2}"

    if [[ "${result}" == "" && "${server_message}" == "" ]]; then
        error_log "UNKNOWN ERROR: something went wrong with the request. Please try again."
    elif [[ "${result}" == "" ]]; then
        error_log "${server_message}"
    fi
}


  # checks desired JSON key/values for validity
function validate_values_from_ims(){
  log_func "${FUNCNAME[0]}"
    local -r server_message="${1}"
    local -r host="${2}"
    local -r secure_port="${3}"
    local -r interface="${4}"
    local -r netbeez_agent_pem="${5}"
    local -r netbeez_agent_pem_md5="${6}"
    
    log "validating <host>: ${host}"
    check_result "${host}" "${server_message}"

    log "validating <server port>: ${secure_port}"
    check_result "${secure_port}" "${server_message}"

    log "validating <interface>: ${interface}"
    check_result "${interface}" "${server_message}"

    log "validating <netbeez_agent.pem>: (not printing for security)"
    check_result "${netbeez_agent_pem}" "${server_message}"

    log "validating <netbeez_agent.pem.md5>: ${netbeez_agent_pem_md5}"
    check_result "${netbeez_agent_pem_md5}" "${server_message}"

    log "validating the server response message: ${server_message}"
    check_result "${server_message}" "${server_message}"
} 


  # backup the config file just in case
  # if this config file isn't here there's something wrong with this install
function backup_config_file(){
  log_func "${FUNCNAME[0]}"
    if [[ ! -f "${CONFIG_FOLDER}/${CONFIG_FILE}" ]]; then
        error_log "CONFIG file (${CONFIG_FOLDER}/${CONFIG_FILE}) does not exist. Something went wrong during the installation."
    else
        cp "${CONFIG_FOLDER}/${CONFIG_FILE}" "${CONFIG_FOLDER}/${CONFIG_FILE}.bak"
    fi
}


  # update the config file with new information
function update_config_file(){
  log_func "${FUNCNAME[0]}"
    log "updating the ${CONFIG_FOLDER}/${CONFIG_FILE} config file"
    #ex. {"host":"hostname.netbeezcloud.net", "secure_port":"20018", "interfaces":"eth0", "model":"software-debian"}
    local -r host="${1}"
    local -r secure_port="${2}"
    local -r interface="${3}"
    # parse model from current config file
    local -r config_data=$(cat "${CONFIG_FOLDER}/${CONFIG_FILE}" | sed 's/{\|}//g')
    local -r model=$(find_value_by_key "model" "${config_data}")
    # create config file
    local -r config='{\"host\":\"'"${host}"'\", \"secure_port\":\"'"${secure_port}"'\", \"model\":\"'"${model}"'\"}'
    # write it
    write_to_disk "${config}" "${CONFIG_FOLDER}/${CONFIG_FILE}"
}


  # ########################################
  # ########################################
function main_self_configure(){
    log_func "${FUNCNAME[0]}"
    # this function will self configure an agent
    # from info contained on the IMS
    log "CONFIGURING Netbeez Agent from Netbeez Server"

    log "BEGINNING to self-configure this agent"
    
    # does the required config file exist
    backup_config_file
    
    # REQUEST DATA
    log "REQUESTING information from Netbeez"
    local -r ims_config="$(request_config_data)"
    
    # PARSE DATA
    log "parsing information from Netbeez"
    local -r host="$(find_value_by_key "host" "${ims_config}")"
    local -r secure_port="$(find_value_by_key "secure_port" "${ims_config}")"
    local -r interface="$(find_value_by_key "interface" "${ims_config}")"
    local -r netbeez_agent_pem="$(find_value_by_key "netbeez_agent_pem" "${ims_config}")"
    local -r netbeez_agent_pem_md5="$(find_value_by_key "netbeez_agent_pem_md5" "${ims_config}")"
    local -r server_message="$(find_value_by_key "msg" "${ims_config}")"

    # CHECK RESULTS
    log "VALIDATING the results from Netbeez"
    validate_values_from_ims "${server_message}" "${host}" "${secure_port}" "${interface}" "${netbeez_agent_pem}" "${netbeez_agent_pem_md5}" 

    # VERIFY KEY
    log "UPDATING agent with Netbeez Server information"
    write_agent_pem "${netbeez_agent_pem}" "${netbeez_agent_pem_md5}"
    update_config_file "${host}" "${secure_port}" "${interface}"
 }
  # ########################################
  # ########################################







#########################
# BLOCK: SOFTWARE AGENT INIT  ##
#########################
# https://netbeez.zendesk.com/hc/en-us/articles/207989403-Install-NetBeez-agents-All-versions-

function get_debian_codename(){
    log_func "${FUNCNAME[0]}"
    echo "$(lsb_release -cs)"
}


function add_x86_netbeez_repo_source(){
    log_func "${FUNCNAME[0]}"

    local -r debian_codename="$(get_debian_codename)"
  	echo "deb [arch=amd64] http://repo.netbeez.net ${debian_codename} main" \
        | tee /etc/apt/sources.list.d/netbeez.list
}


function add_arm_netbeez_repo_source(){
    log_func "${FUNCNAME[0]}"

    local -r debian_codename="$(get_debian_codename)"
	echo "deb http://repo.netbeez.net ${debian_codename} main" \
        | tee /etc/apt/sources.list.d/netbeez.list
}


# add the netbeez repo server to apt-get based on cpu architecture 
function add_netbeez_repo_source(){
    log_func "${FUNCNAME[0]}"
    # Add the NetBeez software repository, update the database, and install the netbeez-agent package:
    local -r machine_architecture="$(get_machine_architecture)"

    if [[ "${machine_hardware_name}" == "x86_64" ]]; then
        add_x86_netbeez_repo_source
    else
        add_arm_netbeez_repo_source
    fi
}


# install the netbeez agent software
function install_netbeez_agent(){
    log_func "${FUNCNAME[0]}"

    wget -O - http://repo.netbeez.net/netbeez_pub.key \
        | apt-key add -
    apt-get update
    apt-get install -y netbeez-agent
}


# ########################################
# ########################################
function main_software_agent_initialization(){
    log_func "${FUNCNAME[0]}"
    # this function will add netbeez repos
    # > get config info from the ims
    # > then restart the agent process
    log "ADDING Netbeez repos"
    add_netbeez_repo_source

    log "INSTALLING Netbeez Agent software"
    install_netbeez_agent
}
  # ########################################
  # ########################################



#########################
# BLOCK: RPI AGENT INIT  #######
#########################

  

# backup the blacklist file
function backup_blacklist_file(){
    log_func "${FUNCNAME[0]}"

    cp -a "${BLACKLIST_FILE}" "${BLACKLIST_FILE_BAK}"
}


# blacklist the rpi3 wireless card
function blacklist_wireless_card(){
    log_func "${FUNCNAME[0]}"
    log "appending disable wifi text to ${BLACKLIST_FILE}"

    backup_blacklist_file

    local -ra appendString=(
      "${DISABLED_WIRELESS_WRAPPER_STRING}"
      "#wifi"
      " blacklist brcmfmac"
      " blacklist brcmutil"
      ""
      "#bt"
      " blacklist btbcm"
      " blacklist hci_uart"
      "${DISABLED_WIRELESS_WRAPPER_STRING}"
    )
    ( IFS=$'\n'; echo "${appendString[*]}" >> "${BLACKLIST_FILE}" )
}


# unblacklist the rpi3 wireless card
function unblacklist_wireless_card(){
    log_func "${FUNCNAME[0]}"
    backup_blacklist_file
    # remove the blacklist lines between (and including) the DISABLED_WIRELESS_WRAPPER_STRING
    sed --in-place '/'"${DISABLED_WIRELESS_WRAPPER_STRING}"'/,/'"${DISABLED_WIRELESS_WRAPPER_STRING}"'/d' "${BLACKLIST_FILE}"
}

# prompt the user to disable the rpi3 onboard wireless card
function prompt_disable_wireless(){
    log_func "${FUNCNAME[0]}"
    local -r yes_response="y"
    local -r no_response="n"
    local is_done="false"
    local response=""
    
    while [ "${is_done}" == "false" ]; do
        log "It looks this machine is a Raspberry Pi 3."
        log "Would you like to disable (via blacklist) the **ONBOARD** wireless network interface? (y/n)"
        log "This will connect your hardware to the Netbeez Dashboard as a **WIRED** agent"
        log "WARNING: this will reboot your Raspberry Pi 3 automatically"

        read response

        if [[ "${response}" == "${yes_response}" ]]; then
            log
            log "IMPORTANT! The onboard wireless will be disabled."
            log "IMPORTANT! You may want to take note of this."
            log "IMPORTANT! TO RUN INTERFACE CONFIGURATION AGAIN USE THE FLAG --modify-interface"

            blacklist_wireless_card

            is_done="true"

        elif [[ "${response}" == "${no_response}" ]]; then
            log
            log "IMPORTANT! The onboard wireless will **NOT** change / stay enabled."
            log "IMPORTANT! You may want to take note of this."
            is_done="false"
        else
            clear
            log
            print_prompt_spacer 3
            log "WARNING!"
            log "WARNING: you gave invalid input."
            log "WARNING: you must enter 'y' or 'n'."
            log
        fi
    done
}


# prompt the user to enable the rpi3 onboard wireless card
function prompt_enable_wireless(){
    log_func "${FUNCNAME[0]}"
    local -r yes_response="y"
    local -r no_response="n"
    local is_done="false"
    local response=""

    while [ "${is_done}" == "false" ]; do
        log "It looks this machine is a Raspberry Pi 3."
        log "Would you like to enable the **ONBOARD** wireless network interface? (y/n)"
        log "This will connect your hardware to the Netbeez Dashboard as a **WIFI** agent"
        log "WARNING: this will reboot your Raspberry Pi 3 automatically"

        read response

        if [[ "${response}" == "${yes_response}" ]]; then
            log
            log "IMPORTANT! The onboard wireless will be enabled."
            log "IMPORTANT! You may want to take note of this."
            log "IMPORTANT! TO RUN INTERFACE CONFIGURATION AGAIN USE THE FLAG --modify-interface"

            unblacklist_wireless_card

            is_done="true"

        elif [[ "${response}" == "${no_response}" ]]; then
            log
            log "IMPORTANT! The onboard wireless will **NOT** change / stay disabled."
            log "IMPORTANT! You may want to take note of this."
            is_done="true"
        else
            clear
            log
            print_prompt_spacer 3

            log "WARNING!"
            log "WARNING: you gave invalid input."
            log "WARNING: you must enter 'y' or 'n'."
            log
        fi
    done
  }


  # determines if the user should be prompted to enable the card or disable it
function wireless_configure_prompt(){
    log_func "${FUNCNAME[0]}"
    clear
    echo
    print_prompt_spacer 3
    log "YOUR INPUT IS REQUIRED!"

    touch "${BLACKLIST_FILE}"

    # is on or off?
    if [[ $(cat "${BLACKLIST_FILE}" | grep "${DISABLED_WIRELESS_WRAPPER_STRING}") ]]; then
        # IS CURRENTLY ENABLED
        prompt_enable_wireless
    else
        #IS CURRENT DISABLED
        prompt_disable_wireless
    fi

    print_prompt_spacer 3
    echo
  }


  # ########################################
  # ########################################
function main_rpi_3_initialization(){
    log_func "${FUNCNAME[0]}"
    # > get config info from the ims
    # > then restart the agent process
    log "RUNNING RPI3 INITIALIZATION"
    log "RUNNING INTERFACE SETUP FOR RASPBERRY PI 3"

    wireless_configure_prompt
}
  # ########################################
  # ########################################



function print_dev_mode_warning(){
    log_func "${FUNCNAME[0]}"
    print_prompt_spacer 3
    log "RUNNING IN DEV MODE -- RUNNING IN DEV MODE -- RUNNING IN DEV MODE -- RUNNING IN DEV MODE"
    print_prompt_spacer 3
}


function blacklist_modified_handler(){
    log "DETECTED HARDWARE CHANGE: RASPBERRY PI 3, wireless interface change"
    log "THIS MACHINE IS GOING DOWN **IMMEDIATELY** FOR A REBOOT TO CONFIGURE THE WIRELESS CARD PROPERLY"
    log "the reboot will implicitly pick up the new configuration"
    sudo reboot
}



#########################
# BLOCK: INIT ##################
#########################
function cleanup(){
    rm -rf "${SCRATCH_DIRECTORY}"
}


function initialize(){
    log_func "${FUNCNAME[0]}"
    trap cleanup EXIT

    initialize_input "${ARGS[@]-}"    
    # NOTE: THE check_input FUNCTION WILL EXIT THE SCRIPT IMMEDIATELY IF IT DETECTS SOMETHING WRONG WITH THE INPUT
    check_input # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    # NOTE: THE check_input FUNCTION WILL EXIT THE SCRIPT IMMEDIATELY IF IT DETECTS SOMETHING WRONG WITH THE INPUT
    
    print_machine_information

    if [[ "${IS_DEV}" == "true" ]]; then
        print_dev_mode_warning
    fi
}






#########################
# BLOCK: MAIN ###########
#########################

function main(){
    log_func "${FUNCNAME[0]}"
    initialize

    
    log "STARTING THE AGENT SETUP SCRIPT!"


    # DETECT HARDWARE TYPE
    if [[ "$(is_rpi_3_agent)" == "true"  ]]; then
        main_rpi_3_initialization

    fi

    # IS SOFTWARE OR IS IMAGE
    if [[ "$(is_software_agent)" == "true" ]]; then
        main_software_agent_initialization
    fi

    # gets info from the main netbeez server to configure this hardware
    log "CONFIGURING AGENT FROM NETBEEZ SERVER"
    main_self_configure


    # IF THE WIRELESS INTERFACE (for rpi3 only) WAS CHANGED - REBOOT
    if [[ "$(is_blacklist_changed)" == "true" ]]; then
        blacklist_modified_handler
    else
        # restart the agent processes to use the new configuration
        restart_agent_process
        log "THIS SCRIPT IS COMPLETE"
    fi
}
main

