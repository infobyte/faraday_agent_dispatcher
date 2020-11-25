#!/bin/bash

function help {
    echo ""
    echo "Usage:"
    echo -e "\t ./docker.sh [OPTION]"
    echo ""
    echo -e "\t[OPTION]:"
    echo -e "\t\t-b, --build\tbuild image"
    echo -e "\t\t-r, --run\trun image"
    echo -e "\t|t-h, help\t print this help"
    echo ""


}

if [[ $# -ne 1 ]]; then
    help
    exit -1
fi

docker_tag="faraday-docker"
option="$1"

if [[ "$option" == "-b" ]] || [[ "$option" == "--build" ]]; then
    echo "Building . . ."
    sudo docker build . -t $docker_tag

elif [[ "$option" == "-r" ]] || [[ "$option" == "--run" ]]; then
    echo "Running . . ."
    sudo docker container run -it $docker_tag

elif [[ "$option" == "-h" ]] || [[ "$option" == "--help" ]]; then
    help

else
    echo ""
    echo "Error: option \"$option\" not found."
    help
    exit -1
fi
