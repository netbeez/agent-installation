
SECRET="3e07153e23daf635e1b073520e7c5b8766accea5"

AGENT_PEM_FILE="netbeez-agent.pem"
URL="https://ims.netbeez.net/"
END_POINT="apis/v1/agent_setup"
IMS_URL="$URL$END_POINT"

log(){
  local msg="$1"
  echo "$msg"
}

error(){
  local msg="$1"
  log "ERROR: $msg"
}

error_exit(){
  local msg="$1"
  error "EXITING SCRIPT: $msg"
  error "EXITING SCRIPT: If you're stuck, contact support@netbeez.net"
  exit "$ERROR"
}




find_value_by_key(){
    # ###################
    # awk sets RS and FS so that 'k1:v1,...,kn:vn' is
    # "formatted" into a 2D table
    # then matches the key/$1 and prints value/$2
    # ###################
    local key="$1"
    local json="$2"

    printf "$json" | awk -v key="\"$key\"" 'BEGIN{ RS=","; FS=":"; }; $1 ~ key {print $2}' | sed 's/"//g'
  }

  replace_value_by_key(){
    # replaces a value associated with a key
    # for example, foo:bar maybe become foo:rab
    local key="$1"
    local new_value="$2"
    local json="$3"

    cat "$json" | perl -pe "s/\"host\":\".*?\",/\"host\":\"$new_value\",/g"
  }

  write_to_disk(){
    # writes data to disk
    local data="$1"
    local location="$2"
    bash -c "echo \"$data\" > \"$location\""
  }

  verify_md5(){
    # this verifies md5s for a file on disk
    # > create new md5: new_md5 = md5(file_on_disk)
    # > then compare: new_md5 == given_md5
    local check_me="$1"
    local given_md5=$(echo "$2" | cut -d' ' -f1)
    local new_md5=$(md5sum "$check_me" | cut -d' ' -f1)
    # new_md5="hello wrold" #this is used to test failed md5s

    local result=$(echo "$given_md5" | grep "$new_md5")
    # echo "$result"
    if [[ "$result" == "" ]]; then
      echo "$ERROR"
    else
      echo "$PASS"
    fi
  }

  process_agent_pem(){
    # 1. writes agent_pem to disk
    # 2. verifies the integrity of agent_pem
    # 3. moves agent_pem to proper location
    local netbeez_agent_pem="$1"
    local netbeez_agent_pem_md5="$2"

    log "VERIFYING key integrity"
    # write netbeez_agent.pem to disk
    echo -n "$netbeez_agent_pem" > "$AGENT_PEM_FILE"
    #
    # local is_okay=$(verify_md5 "$AGENT_PEM_FILE" "$netbeez_agent_pem_md5")
    # if [[ "$is_okay" == "$PASS" ]]; then
    # 	echo "good"
    #   # mkdir -p "$CONFIG_FOLDER"
    #   # mv "$AGENT_PEM_FILE" "$CONFIG_FOLDER/$AGENT_PEM_FILE"
    # else
    #   error_exit "THE key could not be verified"
    # fi
  }

  request_config_data(){
    #get config data from the ims
    echo $(curl --silent \
                --request POST "$IMS_URL" \
                --insecure \
                --data "secret=$SECRET" \
                | sed 's/{\|}//g')
  }

  check_result(){
    # if any of parsed server values are empty, then something went wrong
    # if we have a message from the server then it at least got that far
    local result="$1"
    local server_message="$2"
    if [[ "$result" == "" && "$server_message" == "" ]]; then
      error_exit "UNKNOWN ERROR: something went wrong with the request. Please try again."
    elif [[ "$result" == "" ]]; then
      error_exit "$server_message"
    fi
  }

  check_required_files(){
    if [[ ! -f "$CONFIG_FOLDER/$CONFIG_FILE" ]]; then
      error_exit "CONFIG file ($CONFIG_FOLDER/$CONFIG_FILE) does not exist. Something went wrong during the installation."
    else
      cp "$CONFIG_FOLDER/$CONFIG_FILE" "$CONFIG_FOLDER/$CONFIG_FILE.bak"
    fi
  }

  update_config_file(){
    #ex. {"host":"hostname.netbeezcloud.net", "secure_port":"20018", "interfaces":"eth0", "model":"software-debian"}
    local host="$1"
    local secure_port="$2"
    local interface="$3"
    # parse model from current config file
    local config_data=$(cat "$CONFIG_FOLDER/$CONFIG_FILE" | sed 's/{\|}//g')
    local model=$(find_value_by_key "model" "$config_data")
    # create config file
    local config='{\"host\":\"'"$host"'\", \"secure_port\":\"'"$secure_port"'\", \"interfaces\":\"'"$interface"'\", \"model\":\"'"$model"'\"}'
    # write it
    write_to_disk "$config" "$CONFIG_FOLDER/$CONFIG_FILE"
  }

  main_self_configure(){
    # REQUEST DATA
    ims_config=$(request_config_data)
    # PARSE DATA
    host=$(find_value_by_key "host" "$ims_config")
    secure_port=$(find_value_by_key "secure_port" "$ims_config")
    interface=$(find_value_by_key "interface" "$ims_config")
    netbeez_agent_pem=$(find_value_by_key "netbeez_agent_pem" "$ims_config")
    netbeez_agent_pem_md5=$(find_value_by_key "netbeez_agent_pem_md5" "$ims_config")
    server_message=$(find_value_by_key "msg" "$ims_config")

    # VERIFY KEY
    process_agent_pem "$netbeez_agent_pem" "$netbeez_agent_pem_md5"


    my_md5=$(md5 $AGENT_PEM_FILE | awk -F'= ' '{ print $2 '})
    ims_md5=$(echo $netbeez_agent_pem_md5 | awk '{ print $1 }')

    if [ "$my_md5" == "$ims_md5" ]; then
    	echo "pass"
    else
    	echo "fail"
    fi
  }


  main_self_configure




