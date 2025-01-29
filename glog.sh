#!/bin/bash

# Default list of languages

DEFAULT_LANGS=("c" "java" "javascript" "python" "kotlin" "php" "go" "ruby" "swift" "csharp" "oss" "php-stan" "git" "terraform")

# Function to detect programming languages in the project directory
detect_languages() {
  local project_dir="$1"
  local -A languages
  for file in $(find "$project_dir" -type f); do
    case "${file##*.}" in
      c|cpp|h|hpp)        languages["cpp"]=1 ;;
      java|class)         languages["java"]=1 ;;
      js)                 languages["javascript"]=1 ;;
      py)                 languages["python"]=1 ;;
      kotlin|kt)          languages["kotlin"]=1 ;;
      php)                languages["php"]=1 ;;
      go)                 languages["go"]=1 ;;
      rb)                 languages["ruby"]=1 ;;
      swift)              languages["swift"]=1 ;;
      cs)                 languages["csharp"]=1 ;;
      tf)                 languages["terraform"]=1 ;;
      git)                languages["git"]=1 ;;
      # Add more languages as needed
    esac
  done
  echo "${!languages[@]}"
}

image_exists() {
  local image_name="$1"
  if docker image inspect "$image_name" > /dev/null 2>&1; then
    return 0
  else
    return 1
  fi
}

# Function to clean language
clean_lang() {
    local lang=$1
    IMAGE_NAME="glog-scan-$lang"
    containers=$(docker ps -a | grep "$IMAGE_NAME" | awk '/ / { print $1 }')
    if [ -n "$containers" ]; then
        for container in $containers; do
          echo "Stopping and removing container: $container ..."
          docker stop "$container"
          docker rm "$container"
        done
    else
        echo "No containers to stop and remove."
    fi
    images=$(docker image ls | grep "$IMAGE_NAME" | awk '/ / { print $1 }')
    if [ -n "$images" ]; then
        for image in $images; do
            echo "Removing image: $image..."
            docker image rm "$image"
        done
    else
        echo "No images to stop and remove."
    fi
}

build_lang() {
    local lang=$1
    IMAGE_NAME="glog-scan-$lang"
    SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
    clean_lang $lang
    echo "Docker build $IMAGE_NAME ..."
    docker build --build-arg LANGUAGE="$lang" --build-arg GITHUB_TOKEN="$GITHUB_TOKEN"  -t $IMAGE_NAME $SCRIPT_DIR
}

# Function to scan language and path
scan_lang() {
    local lang=$1
    local path=$2
    local ignore=$3
    IMAGE_NAME="glog-scan-$lang"
    if ! image_exists "$IMAGE_NAME"; then
        build_lang $lang
    fi
    docker run --rm -e glogSERVICE="$glog_TOKEN" -e HOST_UID=$(id -u) -e HOST_GID=$(id -g) -e IGNORE="$ignore" -v "$path":/app -v "$(pwd)/.glog:/.glog:rw" "$IMAGE_NAME"
    #docker run -it -e glogSERVICE="$glog_TOKEN" -e HOST_UID=$(id -u) -e HOST_GID=$(id -g) -e IGNORE="$ignore" -v "$path":/app -v "$(pwd)/.glog:/.glog:rw" "$IMAGE_NAME" /bin/bash
}

# Parse arguments

SCAN=false
BUILD=false
CLEAN=false
LANGUAGES=()
IGNORE=""
PROJECT_PATH=""
GITHUB_TOKEN=$GITHUB_TOKEN
glog_TOKEN=$glog_TOKEN

while [[ $# -gt 0 ]]; do
    case $1 in
        scan)
            SCAN=true
            ;;
        build)
            BUILD=true
            ;;
        clean)
            CLEAN=true
            ;;
        --path)
            PROJECT_PATH="$2"
            shift  # Shift to get the value for --path
            ;;
        --lang)
            IFS=',' read -r -a LANGUAGES <<< "$2"
            shift  # Shift to get the value for --lang
            ;;
        --glogtoken)
            glog_TOKEN="$2"
            shift  # Shift to get the value for --glogtoken
            ;;
        --githubtoken)
            GITHUB_TOKEN="$2"
            shift  # Shift to get the value for --githubtoken
            ;;
        --ignore)
            IGNORE="$2"
            shift  # Shift to get the value for --ignore
            ;;
        *)
            echo "Invalid option: $1"
            exit 1
            ;;
    esac
    shift  # Shift to the next argument
done

### Detect languages ###################################

if $CLEAN || $BUILD; then
  # Use default languages if --lang is not provided
  if [ ${#LANGUAGES[@]} -eq 0 ]; then
    LANGUAGES=("${DEFAULT_LANGS[@]}")
  fi
fi

if $SCAN; then
  # Detect the languages if --lang is not provided
  if [ ${#LANGUAGES[@]} -eq 0 ]; then
    LANGUAGES=($(detect_languages "$PROJECT_PATH"))
  fi
fi

########################################################

# Perform actions based on flags
if $CLEAN; then
    for lang in "${LANGUAGES[@]}"; do
        clean_lang $lang
    done
fi

if $BUILD; then
    for lang in "${LANGUAGES[@]}"; do
        build_lang $lang
    done
fi

if $SCAN; then
    if [ -z "$PROJECT_PATH" ]; then
        echo "--path is mandatory for scan operation"
        exit 1
    fi
    for lang in "${LANGUAGES[@]}"; do
        echo "Analyzing language: $lang"
        scan_lang "$lang" "$PROJECT_PATH" "$IGNORE"
    done
fi